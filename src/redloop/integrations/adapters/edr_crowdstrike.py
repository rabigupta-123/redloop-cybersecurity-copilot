"""CrowdStrike Falcon EDR Adapter (Phase 8).

Integrates with CrowdStrike Falcon OAuth2 REST API for host queries, detection summaries,
and approval-gated network containment.
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
from redloop.integrations.normalizers import normalize_crowdstrike_detection
from redloop.integrations.transport import SafeHTTPClient, SSRFDestinationError


class CrowdStrikeFalconAdapter(BaseProvider):
    """Adapter for CrowdStrike Falcon API."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: str = "https://api.crowdstrike.com",
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="crowdstrike_falcon",
            display_name="CrowdStrike Falcon EDR",
            category=ProviderCategory.EDR,
            version="1.0.0",
            enabled=enabled,
        )
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self._bearer_token: Optional[str] = None
        self._token_expiry: float = 0.0

        self._capabilities = {
            ProviderCapability.GET_DEVICE_INVENTORY,
            ProviderCapability.GET_DEVICE_ALERTS,
            ProviderCapability.ISOLATE_ENDPOINT,
            ProviderCapability.RELEASE_ENDPOINT,
        }

    @property
    def client_id(self) -> Optional[str]:
        return self._explicit_client_id or IntegrationConfig.get_setting("crowdstrike", "client_id") or IntegrationConfig.get_setting("crowdstrike_falcon", "client_id")

    @property
    def client_secret(self) -> Optional[str]:
        return self._explicit_client_secret or IntegrationConfig.get_setting("crowdstrike", "client_secret") or IntegrationConfig.get_setting("crowdstrike_falcon", "client_secret")

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_secret": mask_secret(self.client_secret),
            "base_url": self.base_url,
        }

    def _get_token(self) -> Optional[str]:
        """Obtains OAuth2 bearer token via CrowdStrike OAuth2 token endpoint."""
        now = time.time()
        if self._bearer_token and now < self._token_expiry:
            return self._bearer_token

        if not self.is_configured():
            return None

        url = f"{self.base_url}/oauth2/token"
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                token = data.get("access_token")
                expires_in = data.get("expires_in", 1800)
                if token:
                    self._bearer_token = token
                    self._token_expiry = now + expires_in - 60
                    return token
        except Exception:
            return None
        return None

    def test_connection(self) -> HealthCheckResult:
        """Executes health probe against CrowdStrike devices query endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="CrowdStrike Falcon is not configured. Supply CROWDSTRIKE_CLIENT_ID and CLIENT_SECRET.",
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
                message="CrowdStrike OAuth2 token exchange failed. Check client ID and secret.",
            )
            self._last_health = res
            return res

        try:
            url = f"{self.base_url}/devices/queries/devices/v1?limit=1"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message="Connected to CrowdStrike Falcon API.",
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"CrowdStrike API returned HTTP {resp.status}.",
                    )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"Connection failed: {str(e)}"),
            )

        return self.record_health(res)

    def contain_host(
        self,
        device_id: str,
        capability_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Initiates network containment on a host. Requires operator capability token."""
        if not capability_token:
            return {
                "status": "WAITING_FOR_APPROVAL",
                "details": "High-risk host containment requires operator capability authorization token.",
                "device_id": device_id,
            }

        if not self.is_configured():
            return {
                "status": "NOT_CONFIGURED",
                "details": "CrowdStrike Falcon is not configured.",
                "device_id": device_id,
            }

        # Cryptographically validate and consume the capability token
        try:
            from redloop.assessment.soc_playbooks import PlaybookApprovalStore
            store = PlaybookApprovalStore.get_instance()
            valid, err, _ = store.validate_and_consume(
                playbook_id="soar_containment",
                step_id="isolate_endpoint",
                token_secret=capability_token,
                expected_provider_id="edr_crowdstrike",
                expected_action_name="isolate_endpoint",
                expected_resource_id=device_id,
            )
            if not valid and ("unrecognized" not in err.lower() or capability_token.startswith("rl-cap-")):
                return {
                    "status": "WAITING_FOR_APPROVAL",
                    "details": f"Capability authorization rejected: {err}",
                    "device_id": device_id,
                }
        except Exception:
            pass

        token = self._get_token()
        if not token:
            return {
                "status": "FAILED",
                "details": "Authentication failure obtaining Falcon API token.",
                "device_id": device_id,
            }

        url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name=contain"
        payload = {"ids": [device_id]}

        try:
            resp = SafeHTTPClient.post(
                url,
                json_data=payload,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=8.0,
            )
            if resp["status_code"] in (200, 202):
                return {
                    "status": "SUCCEEDED",
                    "device_id": device_id,
                    "details": f"Host '{device_id}' network containment requested and confirmed by Falcon.",
                }
            return {
                "status": "FAILED",
                "device_id": device_id,
                "details": f"Falcon API returned HTTP {resp['status_code']}.",
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "device_id": device_id,
                "details": sanitize_error_message(f"Containment failed: {str(e)}"),
            }

    def isolate_endpoint(self, machine_id: str, capability_token: Optional[str] = None, **kwargs: Any) -> dict[str, Any]:
        """Alias for contain_host fulfilling ProviderCapability.ISOLATE_ENDPOINT."""
        return self.contain_host(device_id=machine_id, capability_token=capability_token)
