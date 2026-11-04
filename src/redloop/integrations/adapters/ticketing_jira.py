"""Atlassian Jira Incident Ticketing Adapter (Phase 8).

Integrates with Jira REST API (v2/v3) for incident ticket creation, status transitions,
and evidence linking with idempotency keys and secret scrubbing.
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


class JiraAdapter(BaseProvider):
    """Adapter for Atlassian Jira REST API."""

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        project_key: str = "SEC",
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="jira",
            display_name="Atlassian Jira Service Management",
            category=ProviderCategory.TICKETING,
            version="v3",
            enabled=enabled,
        )
        self._explicit_url = url
        self._explicit_username = username
        self._explicit_token = api_token
        self.project_key = project_key
        self._created_tickets: dict[str, str] = {}  # idempotency_key -> ticket_key

        self._capabilities = {
            ProviderCapability.CREATE_INCIDENT_TICKET,
            ProviderCapability.UPDATE_INCIDENT_TICKET,
            ProviderCapability.ATTACH_EVIDENCE_REFERENCE,
            ProviderCapability.SEND_NOTIFICATION,
        }

    @property
    def url(self) -> Optional[str]:
        return self._explicit_url or IntegrationConfig.get_setting("jira", "url")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("jira", "username") or IntegrationConfig.get_setting("jira", "user")

    @property
    def api_token(self) -> Optional[str]:
        return self._explicit_token or IntegrationConfig.get_setting("jira", "api_token") or IntegrationConfig.get_setting("jira", "token")

    def is_configured(self) -> bool:
        return bool(self.url and self.username and self.api_token)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "username": self.username,
            "api_token": mask_secret(self.api_token),
            "project_key": self.project_key,
        }

    def _get_headers(self) -> dict[str, str]:
        creds = f"{self.username}:{self.api_token}".encode("utf-8")
        b64 = base64.b64encode(creds).decode("utf-8")
        return {
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def test_connection(self) -> HealthCheckResult:
        """Probes Jira server info endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Jira is not configured. Supply JIRA_URL, JIRA_USER, and JIRA_API_TOKEN.",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            url = f"{self.url.rstrip('/')}/rest/api/2/serverInfo"
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Jira '{data.get('serverTitle', 'Jira')}'.",
                        details={"server_title": data.get("serverTitle"), "version": data.get("version")},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Jira returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Jira authentication failed.",
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

    def create_incident_ticket(
        self,
        summary: str,
        description: str,
        severity: str = "High",
        idempotency_key: Optional[str] = None,
        evidence_references: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Creates an incident issue in Jira with deduplication via idempotency key."""
        if idempotency_key and idempotency_key in self._created_tickets:
            return {
                "status": "ALREADY_EXISTS",
                "issue_key": self._created_tickets[idempotency_key],
                "details": f"Ticket already created for idempotency key '{idempotency_key}'.",
            }

        if not self.is_configured():
            # Return simulated creation in unconfigured / test mode
            sim_key = f"{self.project_key}-SIM-101"
            if idempotency_key:
                self._created_tickets[idempotency_key] = sim_key
            return {
                "status": "SIMULATED",
                "issue_key": sim_key,
                "details": "Jira ticket created in local simulation mode. (SIMULATED)",
            }

        url = f"{self.url.rstrip('/')}/rest/api/2/issue"
        desc_text = description
        if evidence_references:
            desc_text += f"\n\n*Linked Evidence References:*\n" + "\n".join(f"- {e}" for e in evidence_references)

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary[:255],
                "description": desc_text,
                "issuetype": {"name": "Incident"},
            }
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=self._get_headers())

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status in (200, 201):
                    data = json.loads(resp.read().decode("utf-8"))
                    key = data.get("key", "SEC-UNKNOWN")
                    if idempotency_key:
                        self._created_tickets[idempotency_key] = key
                    return {
                        "status": "SUCCEEDED",
                        "issue_key": key,
                        "details": f"Jira incident ticket '{key}' created successfully.",
                    }
                return {"status": "FAILED", "details": f"Jira returned HTTP {resp.status}."}
        except Exception as e:
            return {"status": "FAILED", "details": sanitize_error_message(str(e))}
