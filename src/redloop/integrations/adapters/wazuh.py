"""Wazuh SIEM / XDR Adapter (Phase 8).

Integrates with Wazuh Manager REST API (v4.x) for manager health, agent inventory,
and alert retrieval with strict credential masking and UniversalSecurityEvent normalization.
"""

from __future__ import annotations

import base64
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
    ProviderResponse,
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfig
from redloop.integrations.credentials import mask_secret, sanitize_error_message
from redloop.integrations.normalizers import normalize_wazuh_alert


class WazuhAdapter(BaseProvider):
    """Adapter for Wazuh Manager REST API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="wazuh",
            display_name="Wazuh SIEM & XDR Manager",
            category=ProviderCategory.SIEM,
            version="4.8.0",
            enabled=enabled,
        )
        self._explicit_url = api_url
        self._explicit_username = username
        self._explicit_password = password
        self.verify_ssl = verify_ssl
        self._jwt_token: Optional[str] = None
        self._token_expiry: float = 0.0

        self._capabilities = {
            ProviderCapability.READ_ALERTS,
            ProviderCapability.SEARCH_EVENTS,
            ProviderCapability.GET_AGENT_HEALTH,
        }

    @property
    def api_url(self) -> Optional[str]:
        return self._explicit_url or IntegrationConfig.get_setting("wazuh", "url") or IntegrationConfig.get_setting("wazuh", "api_url")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("wazuh", "username") or IntegrationConfig.get_setting("wazuh", "user")

    @property
    def password(self) -> Optional[str]:
        return self._explicit_password or IntegrationConfig.get_setting("wazuh", "password")

    def is_configured(self) -> bool:
        return bool(self.api_url and self.username and self.password)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "api_url": self.api_url,
            "username": self.username,
            "password": mask_secret(self.password),
            "verify_ssl": self.verify_ssl,
        }

    def _get_auth_headers(self) -> dict[str, str]:
        """Returns bearer auth headers, authenticating if token is missing or expired."""
        now = time.time()
        if self._jwt_token and now < self._token_expiry:
            return {"Authorization": f"Bearer {self._jwt_token}", "Content-Type": "application/json"}

        # Basic Auth for /security/user/authenticate
        creds = f"{self.username}:{self.password}".encode("utf-8")
        b64_creds = base64.b64encode(creds).decode("utf-8")
        auth_url = f"{self.api_url.rstrip('/')}/security/user/authenticate"

        req = urllib.request.Request(auth_url, headers={"Authorization": f"Basic {b64_creds}"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                token = data.get("data", {}).get("token")
                if token:
                    self._jwt_token = token
                    self._token_expiry = now + 900  # 15 minutes TTL
                    return {"Authorization": f"Bearer {self._jwt_token}", "Content-Type": "application/json"}
        except Exception:
            pass

        # Fallback to basic auth header if token endpoint unavailable
        return {"Authorization": f"Basic {b64_creds}", "Content-Type": "application/json"}

    def test_connection(self) -> HealthCheckResult:
        """Executes authenticated health probe against Wazuh manager."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Wazuh integration is not configured. Supply WAZUH_URL, WAZUH_USER, and WAZUH_PASSWORD.",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            headers = self._get_auth_headers()
            status_url = f"{self.api_url.rstrip('/')}/manager/status"
            req = urllib.request.Request(status_url, headers=headers)

            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    manager_status = data.get("data", {})
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Wazuh Manager. Services operational.",
                        details={"manager_status": manager_status},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Wazuh Manager returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Authentication or authorization failed.",
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

    def get_agents(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieves Wazuh agent inventory."""
        if not self.is_configured():
            return []
        try:
            headers = self._get_auth_headers()
            url = f"{self.api_url.rstrip('/')}/agents?limit={limit}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    def get_alerts(self, limit: int = 50) -> list[UniversalSecurityEvent]:
        """Retrieves and normalizes alerts from Wazuh manager."""
        if not self.is_configured():
            return []
        try:
            headers = self._get_auth_headers()
            url = f"{self.api_url.rstrip('/')}/alerts?limit={limit}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                items = data.get("data", {}).get("affected_items", [])
                return [normalize_wazuh_alert(item, provider_id=self.provider_id) for item in items]
        except Exception:
            return []
