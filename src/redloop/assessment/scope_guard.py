"""Machine-enforced, policy-driven scope verification guard.

The machine-readable signed scope.yaml is the authorization contract.
When a target and action are covered by the valid unexpired signed scope,
execution proceeds autonomously within authorization.
Out-of-scope actions and unauthorized operation classes are strictly blocked.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from redloop.assessment.models import OperationClass
from redloop.audit import AuditLogger
from redloop.scope import ScopeEntry, ScopeManager, UnauthorizedTargetError

DEFAULT_ALLOWED_OPERATION_CLASSES = {
    OperationClass.READ_ONLY,
    OperationClass.SAFE_ACTIVE,
}

# Actions that inherently operate on a network port. When the matched scope
# entry restricts ports, these actions must name an authorized port explicitly.
PORT_SCOPED_ACTIONS = frozenset(
    {
        "recon",
        "scan",
        "web_test",
        "web_check",
        "tls_check",
        "api_check",
        "network_discovery",
    }
)


class ScopeBlockedError(Exception):
    """Raised when an operation or target is technically blocked by signed scope."""

    def __init__(self, target: str, action: str, reason: str):
        self.target = target
        self.action = action
        self.reason = reason
        super().__init__(f"Scope blocked: {target} [{action}] - {reason}")


class AssessmentScopeGuard:
    """Enforces machine-readable scope authorization without conversational friction."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        audit: AuditLogger | None = None,
    ):
        self.scope_manager = scope_manager
        self.audit = audit

    def is_authorized(self, target: str, action: str | None = None) -> bool:
        """Check if target (and optionally action) are authorized without raising.

        With no action, this answers only "is this target covered by the signed
        scope?" and does not imply port authorization; port-scoped operations
        must still pass their actual port to `is_target_authorized`.
        """
        try:
            if action is None:
                return self.is_target_scoped(target)
            self.is_target_authorized(target, action)
            return True
        except Exception:
            return False

    def is_target_scoped(self, target: str) -> bool:
        """Return True only if target matches an active, unexpired scope entry."""
        checker = getattr(self.scope_manager, "is_target_in_scope", None)
        if callable(checker):
            try:
                return bool(checker(target))
            except Exception:
                return False
        try:
            self.scope_manager.check(target, "scan", require_port=False)
            return True
        except Exception:
            return False

    def is_target_authorized(
        self,
        target: str,
        action: str,
        port: int | None = None,
        op_class: OperationClass = OperationClass.SAFE_ACTIVE,
        require_port: bool | None = None,
    ) -> ScopeEntry:
        """Check if target, action, port, and operation class are authorized.

        `require_port=None` derives the requirement from the action. Callers
        that enumerate only the ports already authorized by the scope (for
        example, a port scan over `entry.ports`) may pass False explicitly.

        Returns ScopeEntry if authorized.
        Raises ScopeBlockedError if blocked.
        """
        # 1. Scope validity & expiration check
        if not self.scope_manager.is_within_window():
            msg = "Signed scope document has expired"
            if self.audit:
                self.audit.blocked(target, action, "scope_guard", msg)
            raise ScopeBlockedError(target, action, msg)

        # 2. Check the exact action against ScopeManager. There is no fallback:
        # an unrecognized or unlisted action is always denied by the signed scope.
        if require_port is None:
            require_port = action in PORT_SCOPED_ACTIONS
        try:
            entry = self._check_scope(target, action, port, require_port)
        except UnauthorizedTargetError as exc:
            msg = str(exc)
            if self.audit:
                self.audit.blocked(target, action, "scope_guard", msg)
            raise ScopeBlockedError(target, action, msg) from exc

        # Defense in depth for duck-typed scope managers that ignore the
        # require_port hint: never let a port-restricted entry authorize a
        # port-scoped action without an explicit port.
        if (
            require_port
            and port is None
            and getattr(entry, "ports", None) is not None
        ):
            msg = (
                f"no port was specified for port-scoped action '{action}' "
                f"but scope entry restricts ports to {entry.ports}"
            )
            if self.audit:
                self.audit.blocked(target, action, "scope_guard", msg)
            raise ScopeBlockedError(target, action, msg)

        # 3. Check operation class
        allowed_classes_raw = getattr(entry, "allowed_operation_classes", None)
        if allowed_classes_raw:
            allowed_classes = {
                OperationClass(c) for c in allowed_classes_raw if c in OperationClass.__members__
            }
        else:
            allowed_classes = DEFAULT_ALLOWED_OPERATION_CLASSES

        if op_class not in allowed_classes:
            msg = (
                f"Operation class '{op_class.value}' is not authorized in scope "
                f"(authorized classes: {[c.value for c in allowed_classes]})"
            )
            if self.audit:
                self.audit.blocked(target, action, "scope_guard", msg)
            raise ScopeBlockedError(target, action, msg)

        return entry

    def _check_scope(
        self,
        target: str,
        action: str,
        port: int | None,
        require_port: bool,
    ) -> ScopeEntry:
        """Call the scope manager, tolerating duck-typed managers without require_port."""
        try:
            return self.scope_manager.check(
                target, action, port=port, require_port=require_port
            )
        except TypeError as exc:
            if "require_port" not in str(exc):
                raise
            return self.scope_manager.check(target, action, port=port)

    def verify_operation(
        self,
        target: str,
        category: str = "scan",
        port: int | None = None,
        operation_class: OperationClass = OperationClass.SAFE_ACTIVE,
        require_port: bool | None = None,
    ) -> ScopeEntry:
        """Verify target and action within signed scope without conversational friction."""
        return self.is_target_authorized(
            target=target,
            action=category,
            port=port,
            op_class=operation_class,
            require_port=require_port,
        )

    def normalize_target(self, target: str) -> dict[str, Any]:
        """Normalize target into IP, hostname, and target type."""
        target_clean = target.strip().lower()
        if "://" in target_clean:
            from urllib.parse import urlsplit

            parts = urlsplit(target_clean)
            target_clean = parts.hostname or target_clean

        is_ip = False
        is_loopback = False
        try:
            ip_obj = ipaddress.ip_address(target_clean)
            is_ip = True
            is_loopback = ip_obj.is_loopback
        except ValueError:
            is_loopback = target_clean in ("localhost", "127.0.0.1", "::1")

        return {
            "raw": target,
            "normalized": target_clean,
            "is_ip": is_ip,
            "is_loopback": is_loopback,
        }

    def validate_resolved_ip(self, target_hostname: str, resolved_ip: str, action: str = "scan") -> bool:
        """Verify that resolved IP address is authorized under scope.
        Blocks SSRF/DNS rebinding to private/loopback/link-local addresses unless target itself is explicitly authorized for it.
        """
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
                norm = self.normalize_target(target_hostname)
                if not norm.get("is_loopback"):
                    msg = f"Security block: Hostname '{target_hostname}' resolved to private/loopback address '{resolved_ip}', which is prohibited by policy."
                    if self.audit:
                        self.audit.blocked(target_hostname, action, "scope_guard", msg)
                    raise ScopeBlockedError(target_hostname, action, msg)
            self.is_target_authorized(resolved_ip, action)
            return True
        except ScopeBlockedError:
            raise
        except Exception as exc:
            msg = f"Resolved IP '{resolved_ip}' for '{target_hostname}' is not authorized: {exc}"
            if self.audit:
                self.audit.blocked(target_hostname, action, "scope_guard", msg)
            raise ScopeBlockedError(target_hostname, action, msg) from exc

    def is_target_allowed(self, target: str, ports: list[int] | None = None) -> tuple[bool, str]:
        """Convenience method returning (is_authorized, reason) without throwing exceptions."""
        try:
            port_to_check = ports[0] if ports else None
            self.is_target_authorized(
                target,
                "scan",
                port=port_to_check,
                require_port=bool(ports),
            )
            return True, "AUTHORIZED"
        except ScopeBlockedError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)

