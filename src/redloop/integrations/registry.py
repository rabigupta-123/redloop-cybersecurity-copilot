"""Enterprise Integration Gateway Registry (Phase 8).

Central registry and lifecycle manager for all external security provider adapters.
Guarantees clean local-first fallback when providers are absent or unconfigured.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.adapters import (
    ActiveDirectoryAdapter,
    CrowdStrikeFalconAdapter,
    DefenderForEndpointAdapter,
    ElasticSecurityAdapter,
    EntraIDAdapter,
    JiraAdapter,
    ServiceNowAdapter,
    SplunkAdapter,
    WazuhAdapter,
)
from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)


class IntegrationRegistry:
    """Thread-safe centralized registry for enterprise security provider adapters."""

    _instance: Optional["IntegrationRegistry"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._op_lock = threading.RLock()
        self._providers: dict[str, BaseProvider] = {}
        self._sync_jobs: dict[str, dict[str, Any]] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._init_defaults()

    @classmethod
    def get_instance(cls) -> "IntegrationRegistry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _init_defaults(self) -> None:
        """Initializes standard provider adapters with offline/local fallback."""
        default_adapters = [
            WazuhAdapter(),
            ElasticSecurityAdapter(),
            SplunkAdapter(),
            DefenderForEndpointAdapter(),
            CrowdStrikeFalconAdapter(),
            EntraIDAdapter(),
            ActiveDirectoryAdapter(),
            JiraAdapter(),
            ServiceNowAdapter(),
        ]
        for adapter in default_adapters:
            self._providers[adapter.provider_id] = adapter

    def register(self, provider: BaseProvider) -> None:
        """Registers or replaces a provider adapter."""
        with self._op_lock:
            self._providers[provider.provider_id] = provider
            self._log_audit("REGISTER", provider.provider_id, f"Registered provider '{provider.display_name}'.")

    ALIAS_MAP = {
        "elastic": "elastic_security",
        "defender": "defender_endpoint",
        "crowdstrike": "crowdstrike_falcon",
        "ad": "active_directory",
    }

    def get_provider(self, provider_id: str) -> Optional[BaseProvider]:
        """Looks up a provider adapter by ID or known alias."""
        with self._op_lock:
            pid = provider_id.lower().strip()
            pid = self.ALIAS_MAP.get(pid, pid)
            return self._providers.get(pid)

    def list_providers(self, category: Optional[ProviderCategory] = None) -> list[dict[str, Any]]:
        """Returns safe metadata for registered providers (no secrets)."""
        with self._op_lock:
            out = []
            for p in self._providers.values():
                if category is None or p.category == category:
                    out.append(p.to_dict())
            return out

    def test_provider(self, provider_id: str) -> HealthCheckResult:
        """Probes live connectivity for a provider adapter."""
        p = self.get_provider(provider_id)
        if not p:
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message=f"Provider '{provider_id}' is not registered in IntegrationRegistry.",
            )
            return res
        res = p.test_connection()
        self._log_audit("TEST_CONNECTION", provider_id, f"Health check: {res.status.value} ({res.message})")
        return res

    def enable_provider(self, provider_id: str, enabled: bool = True) -> bool:
        """Toggles operational state of an integration."""
        with self._op_lock:
            p = self.get_provider(provider_id)
            if not p:
                return False
            p.enabled = enabled
            action = "ENABLED" if enabled else "DISABLED"
            self._log_audit(action, provider_id, f"Provider '{p.display_name}' {action.lower()}.")
            return True

    def sync_provider(self, provider_id: str, limit: int = 50) -> list[UniversalSecurityEvent]:
        """Pulls events from a specific provider and returns normalized UniversalSecurityEvents."""
        p = self.get_provider(provider_id)
        if not p:
            return []

        events: list[UniversalSecurityEvent] = []
        if isinstance(p, WazuhAdapter):
            events = p.get_alerts(limit=limit)
        elif isinstance(p, ElasticSecurityAdapter):
            events = p.get_alerts(limit=limit)
        elif isinstance(p, SplunkAdapter):
            events = p.search_events("index=* (sourcetype=access_combined OR sourcetype=sysmon)", limit=limit)
        elif isinstance(p, DefenderForEndpointAdapter):
            events = p.get_alerts(limit=limit)

        self._log_audit("SYNC", provider_id, f"Synchronized {len(events)} events.")
        return events

    def start_sync_job(self, provider_id: Optional[str] = None, limit_per_provider: int = 50) -> str:
        """Initiates a background or synchronous telemetry synchronization job."""
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()
        total_ingested = 0

        with self._op_lock:
            targets = [self.get_provider(provider_id)] if provider_id else list(self._providers.values())
            for t in targets:
                if t and t.enabled and t.is_configured():
                    evs = self.sync_provider(t.provider_id, limit=limit_per_provider)
                    total_ingested += len(evs)

            self._sync_jobs[job_id] = {
                "job_id": job_id,
                "provider_id": provider_id or "all",
                "status": "COMPLETED",
                "total_ingested": total_ingested,
                "created_at": now,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            return job_id

    def get_sync_job(self, job_id: str) -> Optional[dict[str, Any]]:
        """Retrieves status of a sync job."""
        with self._op_lock:
            return self._sync_jobs.get(job_id)

    def _log_audit(self, action: str, provider_id: str, details: str) -> None:
        entry = {
            "audit_id": f"aud-{uuid.uuid4().hex[:8]}",
            "action": action,
            "provider_id": provider_id,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._audit_log.append(entry)
        if len(self._audit_log) > 500:
            self._audit_log.pop(0)

    def get_audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        """Returns recent integration audit trail entries."""
        with self._op_lock:
            return list(reversed(self._audit_log[-limit:]))
