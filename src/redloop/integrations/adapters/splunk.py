"""Splunk Enterprise & Cloud SIEM Adapter (Phase 8).

Integrates with Splunk REST API (v9.x) for server health, bounded search job execution,
and alert retrieval with read-only SPL guardrails.
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
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfig
from redloop.integrations.credentials import mask_secret, sanitize_error_message
from redloop.integrations.normalizers import normalize_splunk_event

PROHIBITED_SPL_COMMANDS = {
    "delete",
    "outputlookup",
    "outputcsv",
    "collect",
    "sendemail",
    "run",
    "script",
}


class SplunkAdapter(BaseProvider):
    """Adapter for Splunk REST API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 8089,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="splunk",
            display_name="Splunk Enterprise / Cloud SIEM",
            category=ProviderCategory.SIEM,
            version="9.2.0",
            enabled=enabled,
        )
        self._explicit_host = host
        self._port = port
        self._explicit_token = token
        self._explicit_username = username
        self._explicit_password = password

        self._capabilities = {
            ProviderCapability.READ_ALERTS,
            ProviderCapability.SEARCH_EVENTS,
        }

    @property
    def host(self) -> Optional[str]:
        return self._explicit_host or IntegrationConfig.get_setting("splunk", "host") or IntegrationConfig.get_setting("splunk", "url")

    @property
    def port(self) -> int:
        p_str = IntegrationConfig.get_setting("splunk", "port")
        if p_str:
            try:
                return int(p_str)
            except ValueError:
                pass
        return self._port

    @property
    def token(self) -> Optional[str]:
        return self._explicit_token or IntegrationConfig.get_setting("splunk", "token")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("splunk", "username") or IntegrationConfig.get_setting("splunk", "user")

    @property
    def password(self) -> Optional[str]:
        return self._explicit_password or IntegrationConfig.get_setting("splunk", "password")

    @property
    def base_url(self) -> Optional[str]:
        if not self.host:
            return None
        h = self.host.rstrip("/")
        if not h.startswith("http://") and not h.startswith("https://"):
            h = f"https://{h}:{self.port}"
        elif ":" not in h.replace("http://", "").replace("https://", ""):
            h = f"{h}:{self.port}"
        return h

    def is_configured(self) -> bool:
        if not self.host:
            return False
        return bool(self.token or (self.username and self.password))

    def get_public_config(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "token": mask_secret(self.token),
            "username": self.username,
            "password": mask_secret(self.password),
        }

    def _get_headers(self) -> dict[str, str]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Splunk {self.token}"
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            b64_creds = base64.b64encode(creds).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_creds}"
        return headers

    def test_connection(self) -> HealthCheckResult:
        """Executes connection health probe against Splunk server info endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Splunk is not configured. Supply SPLUNK_HOST and SPLUNK_TOKEN (or USER/PASSWORD).",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            url = f"{self.base_url}/services/server/info?output_mode=json"
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    entry = data.get("entry", [{}])[0].get("content", {})
                    server_name = entry.get("serverName", "splunk")
                    version = entry.get("version", "9.x")
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Splunk server '{server_name}' (v{version}).",
                        details={"server_name": server_name, "version": version},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Splunk returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Splunk authentication failed.",
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

    def search_events(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        limit: int = 50,
    ) -> list[UniversalSecurityEvent]:
        """Executes a bounded, read-only SPL search job."""
        if not self.is_configured():
            return []

        # Validate SPL query against prohibited commands
        clean_spl = spl_query.lower()
        for cmd in PROHIBITED_SPL_COMMANDS:
            if f"| {cmd}" in clean_spl or f"|{cmd}" in clean_spl:
                raise ValueError(f"Prohibited non-read-only SPL command '{cmd}' blocked.")

        safe_spl = spl_query.strip()
        if not safe_spl.startswith("search"):
            safe_spl = f"search {safe_spl}"
        if "| head" not in safe_spl:
            safe_spl = f"{safe_spl} | head {min(limit, 100)}"

        # 1. Create Search Job
        job_url = f"{self.base_url}/services/search/jobs?output_mode=json"
        job_data = urllib.parse.urlencode({
            "search": safe_spl,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "exec_mode": "oneshot",
        }).encode("utf-8")

        headers = self._get_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            req = urllib.request.Request(job_url, data=job_data, headers=headers)
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                return [normalize_splunk_event(r, provider_id=self.provider_id) for r in results]
        except Exception:
            return []
