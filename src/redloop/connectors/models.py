"""Data models and manifests for REDLOOP Connector Layer (Phase 2)."""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class TransportType(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    REST = "rest"


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    ACTIVE = "active"


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ConnectorTool(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel = RiskLevel.READ_ONLY


class ConnectorManifest(BaseModel):
    name: str
    transport: TransportType = TransportType.REST
    tools: List[ConnectorTool] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.READ_ONLY
    allowed_scope: List[str] = Field(default_factory=list)
    rate_limit: int = 60  # max requests per minute
    timeout: float = 10.0  # seconds
    last_health: str = "unknown"  # healthy | degraded | unhealthy | unknown
    error_rate: float = 0.0  # 0.0 to 1.0
    id: Optional[str] = None
    enabled: bool = True
    base_url: Optional[str] = None
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    env_keys: List[str] = Field(default_factory=list)  # names of env vars holding secrets (never values)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ConnectorTelemetry(BaseModel):
    connector_id: str
    name: str
    status: str = "healthy"
    p95_latency_ms: float = 0.0
    error_rate: float = 0.0
    last_call: Optional[str] = None
    calls_today: int = 0
    circuit_state: CircuitState = CircuitState.CLOSED

