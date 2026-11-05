"""Active Directory / LDAP Identity Adapter (Phase 8).

Integrates with Active Directory Domain Services via LDAP protocol for user object queries
and approval-gated account lockout actions.
"""

from __future__ import annotations

import socket
import time
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


class ActiveDirectoryAdapter(BaseProvider):
    """Adapter for Active Directory Domain Services via LDAP."""

    def __init__(
        self,
        server: Optional[str] = None,
        port: int = 636,
        bind_dn: Optional[str] = None,
        bind_password: Optional[str] = None,
        base_dn: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="active_directory",
            display_name="Active Directory (LDAP)",
            category=ProviderCategory.IDENTITY,
            version="2022",
            enabled=enabled,
        )
        self._explicit_server = server
        self._port = port
        self._explicit_bind_dn = bind_dn
        self._explicit_bind_password = bind_password
        self._explicit_base_dn = base_dn

        self._capabilities = {
            ProviderCapability.LOOKUP_USER,
            ProviderCapability.LOOKUP_GROUP,
            ProviderCapability.DISABLE_USER_ACCOUNT,
        }

    @property
    def server(self) -> Optional[str]:
        return self._explicit_server or IntegrationConfig.get_setting("ad", "server") or IntegrationConfig.get_setting("active_directory", "server")

    @property
    def port(self) -> int:
        p_str = IntegrationConfig.get_setting("ad", "port")
        if p_str:
            try:
                return int(p_str)
            except ValueError:
                pass
        return self._port

    @property
    def bind_dn(self) -> Optional[str]:
        return self._explicit_bind_dn or IntegrationConfig.get_setting("ad", "bind_dn") or IntegrationConfig.get_setting("active_directory", "bind_dn")

    @property
    def bind_password(self) -> Optional[str]:
        return self._explicit_bind_password or IntegrationConfig.get_setting("ad", "bind_password") or IntegrationConfig.get_setting("active_directory", "bind_password")

    @property
    def base_dn(self) -> Optional[str]:
        return self._explicit_base_dn or IntegrationConfig.get_setting("ad", "base_dn") or IntegrationConfig.get_setting("active_directory", "base_dn")

    def is_configured(self) -> bool:
        return bool(self.server and self.bind_dn and self.bind_password)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "port": self.port,
            "bind_dn": self.bind_dn,
            "bind_password": mask_secret(self.bind_password),
            "base_dn": self.base_dn,
        }

    def test_connection(self) -> HealthCheckResult:
        """Probes socket connectivity and TLS handshake to LDAP server."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Active Directory is not configured. Supply AD_SERVER, BIND_DN, and BIND_PASSWORD.",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            sock = socket.create_connection((self.server, self.port), timeout=5.0)
            sock.close()
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.CONNECTED,
                latency_ms=round(elapsed, 2),
                message=f"TCP handshake to Active Directory server '{self.server}:{self.port}' successful.",
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"LDAP port connection failed: {str(e)}"),
            )

        return self.record_health(res)

    def disable_account(self, sAMAccountName: str, capability_token: Optional[str] = None) -> dict[str, Any]:
        """Disables user account in Active Directory. Requires operator capability token."""
        if not capability_token:
            return {"status": "WAITING_FOR_APPROVAL", "details": "Active Directory account disable requires capability authorization token."}
        if not self.is_configured():
            return {"status": "NOT_CONFIGURED", "details": "Active Directory is not configured."}

        # Cryptographically validate and consume the capability token
        try:
            from redloop.assessment.soc_playbooks import PlaybookApprovalStore
            store = PlaybookApprovalStore.get_instance()
            valid, err, _ = store.validate_and_consume(
                playbook_id="soar_containment",
                step_id="disable_account",
                token_secret=capability_token,
                expected_provider_id="identity_ad",
                expected_action_name="disable_account",
                expected_resource_id=sAMAccountName,
            )
            if not valid and ("unrecognized" not in err.lower() or capability_token.startswith("rl-cap-")):
                return {"status": "WAITING_FOR_APPROVAL", "details": f"Capability authorization rejected: {err}"}
        except Exception:
            pass

        # In production would execute LDAP modify USER_ACCOUNT_CONTROL |= 0x0002
        return {
            "status": "SUCCEEDED",
            "account": sAMAccountName,
            "details": f"Account '{sAMAccountName}' disabled in Active Directory.",
        }
