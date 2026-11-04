"""Enterprise Security Integration Base Interfaces & Types (Phase 8).

Defines provider-neutral abstractions, lifecycle states, and capability models.
"""

from __future__ import annotations

import abc
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ProviderCategory(str, Enum):
    SIEM = "SIEM"
    EDR = "EDR"
    IDENTITY = "IDENTITY"
    TICKETING = "TICKETING"
    NOTIFICATION = "NOTIFICATION"


class ProviderStatus(str, Enum):
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"


class ProviderCapability(str, Enum):
    # SIEM
    READ_ALERTS = "READ_ALERTS"
    SEARCH_EVENTS = "SEARCH_EVENTS"
    STREAM_LOGS = "STREAM_LOGS"
    GET_AGENT_HEALTH = "GET_AGENT_HEALTH"

    # EDR / XDR
    GET_DEVICE_INVENTORY = "GET_DEVICE_INVENTORY"
    GET_DEVICE_HEALTH = "GET_DEVICE_HEALTH"
    GET_DEVICE_ALERTS = "GET_DEVICE_ALERTS"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    RELEASE_ENDPOINT = "RELEASE_ENDPOINT"
    QUARANTINE_FILE = "QUARANTINE_FILE"

    # Identity
    LOOKUP_USER = "LOOKUP_USER"
    LOOKUP_GROUP = "LOOKUP_GROUP"
    GET_AUTH_EVENTS = "GET_AUTH_EVENTS"
    REVOKE_USER_SESSIONS = "REVOKE_USER_SESSIONS"
    DISABLE_USER_ACCOUNT = "DISABLE_USER_ACCOUNT"
    RESET_PASSWORD = "RESET_PASSWORD"

    # Ticketing / Notification
    CREATE_INCIDENT_TICKET = "CREATE_INCIDENT_TICKET"
    UPDATE_INCIDENT_TICKET = "UPDATE_INCIDENT_TICKET"
    ATTACH_EVIDENCE_REFERENCE = "ATTACH_EVIDENCE_REFERENCE"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"


@dataclass
class HealthCheckResult:
    """Standardized result of a provider health probe."""
    status: ProviderStatus
    latency_ms: float
    message: str
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ProviderResponse:
    """Encapsulates the raw response from a security provider API."""
    success: bool
    status_code: int
    data: Any
    error_message: Optional[str] = None
    retrieval_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0
    provider_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseProvider(abc.ABC):
    """Abstract base class for all enterprise security provider adapters."""

    def __init__(
        self,
        provider_id: str,
        display_name: str,
        category: ProviderCategory,
        version: str = "1.0.0",
        enabled: bool = False,
    ) -> None:
        self.provider_id = provider_id
        self.display_name = display_name
        self.category = category
        self.version = version
        self.enabled = enabled
        self._last_health: Optional[HealthCheckResult] = None
        self._capabilities: set[ProviderCapability] = set()

    @property
    def status(self) -> ProviderStatus:
        if not self.is_configured():
            return ProviderStatus.NOT_CONFIGURED
        if self._last_health:
            return self._last_health.status
        return ProviderStatus.UNAVAILABLE

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Returns True only if all required credentials and endpoints are supplied."""
        pass

    @abc.abstractmethod
    def test_connection(self) -> HealthCheckResult:
        """Executes a live health check against the provider endpoint."""
        pass

    def get_health(self) -> HealthCheckResult:
        """Returns the most recent health check result or executes test_connection."""
        if self._last_health is None:
            return self.test_connection()
        return self._last_health

    def get_capabilities(self) -> list[str]:
        """Returns list of capabilities supported by this adapter."""
        return sorted([c.value for c in self._capabilities])

    @abc.abstractmethod
    def get_public_config(self) -> dict[str, Any]:
        """Returns non-sensitive configuration parameters (secrets MUST be masked)."""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Serializes provider status and public configuration safely without secrets."""
        health = self.get_health()
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "category": self.category.value,
            "version": self.version,
            "enabled": self.enabled,
            "is_configured": self.is_configured(),
            "status": health.status.value,
            "last_checked_at": health.checked_at,
            "latency_ms": health.latency_ms,
            "capabilities": self.get_capabilities(),
            "config": self.get_public_config(),
        }
