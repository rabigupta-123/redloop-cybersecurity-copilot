"""Microsoft Defender for Endpoint (MDE) EDR Adapter (Phase 8).

Integrates with Defender for Endpoint REST API for device inventory, alert retrieval,
and approval-gated host isolation actions.
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
from redloop.integrations.normalizers import normalize_defender_alert


class DefenderForEndpointAdapter(BaseProvider):
    """Adapter for Microsoft Defender for Endpoint REST API."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="defender_endpoint",
            display_name="Microsoft Defender for Endpoint",
            category=ProviderCategory.EDR,
            version="1.0.0",
            enabled=enabled,
        )
        self._explicit_tenant_id = tenant_id
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret
        self._bearer_token: Optional[str] = None
        self._token_expiry: float = 0.0

        self._capabilities = {
            ProviderCapability.GET_DEVICE_INVENTORY,
            ProviderCapability.GET_DEVICE_HEALTH,
            ProviderCapability.GET_DEVICE_ALERTS,
            ProviderCapability.ISOLATE_ENDPOINT,
            ProviderCapability.RELEASE_ENDPOINT,
        }

    @property
    def tenant_id(self) -> Optional[str]:
        return self._explicit_tenant_id or IntegrationConfig.get_setting("defender", "tenant_id") or IntegrationConfig.get_setting("defender_endpoint", "tenant_id")

    @property
    def client_id(self) -> Optional[str]:
        return self._explicit_client_id or IntegrationConfig.get_setting("defender", "client_id") or IntegrationConfig.get_setting("defender_endpoint", "client_id")

    @property
    def client_secret(self) -> Optional[str]:
        return self._explicit_client_secret or IntegrationConfig.get_setting("defender", "client_secret") or IntegrationConfig.get_setting("defender_endpoint", "client_secret")

    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_secret": mask_secret(self.client_secret),
        }

    def _get_token(self) -> Optional[str]:
        """Obtains OAuth2 bearer token via Microsoft Entra login endpoint."""
        now = time.time()
        if self._bearer_token and now < self._token_expiry:
            return self._bearer_token

        if not self.is_configured():
            return None

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).encode("utf-8")

        req = urllib.request.Request(token_url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
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
        """Executes health probe against Microsoft Defender Security Center API."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Defender for Endpoint is not configured. Supply DEFENDER_TENANT_ID, CLIENT_ID, and CLIENT_SECRET.",
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
                message="OAuth2 token acquisition failed. Invalid tenant ID, client ID, or secret.",
            )
            self._last_health = res
            return res

        try:
            url = "https://api.securitycenter.microsoft.com/api/machines?$top=1"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message="Connected to Microsoft Defender for Endpoint API.",
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Defender API returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Defender for Endpoint authentication or permission rejected.",
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

    def get_alerts(self, limit: int = 50) -> list[UniversalSecurityEvent]:
        """Retrieves and normalizes alerts from Defender for Endpoint."""
        if not self.is_configured():
            return []
        token = self._get_token()
        if not token:
            return []

        url = f"https://api.securitycenter.microsoft.com/api/alerts?$top={min(limit, 100)}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                alerts = data.get("value", [])
                return [normalize_defender_alert(a, provider_id=self.provider_id) for a in alerts]
        except Exception:
            return []

    def isolate_endpoint(
        self,
        machine_id: str,
        isolation_type: str = "Full",
        comment: str = "Automated SOAR Containment",
        capability_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Isolates a machine via Defender API. Requires operator capability token."""
        if not capability_token:
            return {
                "status": "WAITING_FOR_APPROVAL",
                "details": "High-risk endpoint isolation requires operator capability authorization token.",
                "machine_id": machine_id,
            }

        if not self.is_configured():
            return {
                "status": "NOT_CONFIGURED",
                "details": "Microsoft Defender for Endpoint is not configured.",
                "machine_id": machine_id,
            }

        token = self._get_token()
        if not token:
            return {
                "status": "FAILED",
                "details": "Authentication failure obtaining Defender API token.",
                "machine_id": machine_id,
            }

        url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate"
        body = json.dumps({"Comment": comment, "IsolationType": isolation_type}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status in (200, 201):
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "status": "SUCCEEDED",
                        "machine_id": machine_id,
                        "action_id": data.get("id"),
                        "details": f"Machine '{machine_id}' isolated successfully.",
                    }
                return {
                    "status": "FAILED",
                    "machine_id": machine_id,
                    "details": f"Defender API returned HTTP {resp.status}.",
                }
        except Exception as e:
            return {
                "status": "FAILED",
                "machine_id": machine_id,
                "details": sanitize_error_message(f"Isolation failed: {str(e)}"),
            }
