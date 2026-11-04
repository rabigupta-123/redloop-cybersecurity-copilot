"""Elastic Security SIEM Adapter (Phase 8).

Integrates with Elasticsearch & Kibana Detection Engine for alert retrieval,
parameterized event search, and index status with strict query validation.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
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
from redloop.integrations.normalizers import normalize_elastic_alert


class ElasticSecurityAdapter(BaseProvider):
    """Adapter for Elastic Security SIEM and Elasticsearch REST API."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        alerts_index: str = ".alerts-security.alerts-default*",
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="elastic_security",
            display_name="Elastic Security SIEM",
            category=ProviderCategory.SIEM,
            version="8.14.0",
            enabled=enabled,
        )
        self._explicit_url = url
        self._explicit_api_key = api_key
        self._explicit_username = username
        self._explicit_password = password
        self.alerts_index = alerts_index

        self._capabilities = {
            ProviderCapability.READ_ALERTS,
            ProviderCapability.SEARCH_EVENTS,
        }

    @property
    def url(self) -> Optional[str]:
        return self._explicit_url or IntegrationConfig.get_setting("elastic_security", "url") or IntegrationConfig.get_setting("elastic", "url")

    @property
    def api_key(self) -> Optional[str]:
        return self._explicit_api_key or IntegrationConfig.get_setting("elastic_security", "api_key") or IntegrationConfig.get_setting("elastic", "api_key")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("elastic_security", "username") or IntegrationConfig.get_setting("elastic", "user")

    @property
    def password(self) -> Optional[str]:
        return self._explicit_password or IntegrationConfig.get_setting("elastic_security", "password")

    def is_configured(self) -> bool:
        if not self.url:
            return False
        return bool(self.api_key or (self.username and self.password))

    def get_public_config(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "api_key": mask_secret(self.api_key),
            "username": self.username,
            "password": mask_secret(self.password),
            "alerts_index": self.alerts_index,
        }

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            b64_creds = base64.b64encode(creds).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_creds}"
        return headers

    def test_connection(self) -> HealthCheckResult:
        """Executes connection health probe against Elasticsearch root endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Elastic Security is not configured. Supply ELASTIC_URL and ELASTIC_API_KEY (or USER/PASSWORD).",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            req = urllib.request.Request(self.url.rstrip("/"), headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    cluster_name = data.get("cluster_name", "elasticsearch")
                    version = data.get("version", {}).get("number", "8.x")
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Elastic cluster '{cluster_name}' (v{version}).",
                        details={"cluster_name": cluster_name, "version": version},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Elasticsearch returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Authentication or permission rejected by Elasticsearch.",
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"Connection failed: {str(e)}"),
            )

        return self.record_health(res)

    def get_alerts(self, limit: int = 50, days_back: int = 7) -> list[UniversalSecurityEvent]:
        """Queries and normalizes detection alerts using safe parameterized query DSL."""
        if not self.is_configured():
            return []

        search_dsl = {
            "size": min(limit, 100),
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{days_back}d/d"}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        url = f"{self.url.rstrip('/')}/{self.alerts_index}/_search"
        req = urllib.request.Request(
            url,
            data=json.dumps(search_dsl).encode("utf-8"),
            headers=self._get_headers(),
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                hits = data.get("hits", {}).get("hits", [])
                return [normalize_elastic_alert(hit, provider_id=self.provider_id) for hit in hits]
        except Exception:
            return []
