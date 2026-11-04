"""ServiceNow Incident Table Adapter (Phase 8).

Integrates with ServiceNow REST Table API for incident ticket creation,
updates, and work note attachments.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfig
from redloop.integrations.credentials import mask_secret, sanitize_error_message


class ServiceNowAdapter(BaseProvider):
    """Adapter for ServiceNow Table API."""

    def __init__(
        self,
        instance_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="servicenow",
            display_name="ServiceNow Incident Management",
            category=ProviderCategory.TICKETING,
            version="v1",
            enabled=enabled,
        )
        self._explicit_url = instance_url
        self._explicit_username = username
        self._explicit_password = password
        self._created_incidents: dict[str, str] = {}  # idempotency_key -> incident_number

        self._capabilities = {
            ProviderCapability.CREATE_INCIDENT_TICKET,
            ProviderCapability.UPDATE_INCIDENT_TICKET,
            ProviderCapability.ATTACH_EVIDENCE_REFERENCE,
            ProviderCapability.SEND_NOTIFICATION,
        }

    @property
    def instance_url(self) -> Optional[str]:
        return self._explicit_url or IntegrationConfig.get_setting("servicenow", "url") or IntegrationConfig.get_setting("servicenow", "instance_url")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("servicenow", "username") or IntegrationConfig.get_setting("servicenow", "user")

    @property
    def password(self) -> Optional[str]:
        return self._explicit_password or IntegrationConfig.get_setting("servicenow", "password")

    def is_configured(self) -> bool:
        return bool(self.instance_url and self.username and self.password)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "instance_url": self.instance_url,
            "username": self.username,
            "password": mask_secret(self.password),
        }

    def _get_headers(self) -> dict[str, str]:
        creds = f"{self.username}:{self.password}".encode("utf-8")
        b64 = base64.b64encode(creds).decode("utf-8")
        return {
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> HealthCheckResult:
        """Probes ServiceNow Table API endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="ServiceNow is not configured. Supply SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD.",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            url = f"{self.instance_url.rstrip('/')}/api/now/table/incident?sysparm_limit=1"
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message="Connected to ServiceNow Incident Table API.",
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"ServiceNow returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: ServiceNow authentication rejected.",
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"Connection failed: {str(e)}"),
            )

        return self.record_health(res)

    def create_incident_ticket(
        self,
        short_description: str,
        description: str,
        urgency: str = "1",
        idempotency_key: Optional[str] = None,
        evidence_references: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Creates an incident record in ServiceNow table api."""
        if idempotency_key and idempotency_key in self._created_incidents:
            return {
                "status": "ALREADY_EXISTS",
                "incident_number": self._created_incidents[idempotency_key],
                "details": f"ServiceNow incident already exists for idempotency key '{idempotency_key}'.",
            }

        if not self.is_configured():
            sim_num = "INC0010992"
            if idempotency_key:
                self._created_incidents[idempotency_key] = sim_num
            return {
                "status": "SIMULATED",
                "incident_number": sim_num,
                "details": "ServiceNow incident created in local simulation mode. (SIMULATED)",
            }

        url = f"{self.instance_url.rstrip('/')}/api/now/table/incident"
        work_notes = ""
        if evidence_references:
            work_notes = "Attached Evidence Records: " + ", ".join(evidence_references)

        payload = {
            "short_description": short_description[:160],
            "description": description,
            "urgency": urgency,
            "work_notes": work_notes,
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=self._get_headers())

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status in (200, 201):
                    data = json.loads(resp.read().decode("utf-8"))
                    result = data.get("result", {})
                    num = result.get("number", "INC-UNKNOWN")
                    if idempotency_key:
                        self._created_incidents[idempotency_key] = num
                    return {
                        "status": "SUCCEEDED",
                        "incident_number": num,
                        "sys_id": result.get("sys_id"),
                        "details": f"ServiceNow incident '{num}' created.",
                    }
                return {"status": "FAILED", "details": f"ServiceNow returned HTTP {resp.status}."}
        except Exception as e:
            return {"status": "FAILED", "details": sanitize_error_message(str(e))}
