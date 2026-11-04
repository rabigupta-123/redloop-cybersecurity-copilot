"""REDLOOP Enterprise Security Integrations Gateway (Phase 8).

Provides:
1. Provider-neutral integration architecture for SIEM, EDR/XDR, Identity, and Ticketing systems.
2. Typed provider interfaces, health checks, bounded retries, and strict secret masking.
3. Cross-platform normalization into UniversalSecurityEvent, SOCAlert, and Evidence Ledger.
4. Seamless offline / local-first fallback when external providers are unconfigured or unavailable.
"""

from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.registry import IntegrationRegistry

__all__ = [
    "BaseProvider",
    "HealthCheckResult",
    "ProviderCapability",
    "ProviderCategory",
    "ProviderStatus",
    "IntegrationRegistry",
]
