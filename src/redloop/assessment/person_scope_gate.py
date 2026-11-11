"""Person-Identifying OSINT Scope Gate (Phase L.0).

Enforces strict mandatory authorization before any person-identifying OSINT lookup
(email, phone number, or username) can execute across REST, Chat, or MCP entry points.

Every lookup must satisfy ONE of:
  (a) Self-Lookup: target == operator's own verified identifier (no engagement needed,
      still logged to the cryptographic audit ledger).
  (b) Engagement-Authorized: target is listed inside the currently active, unexpired,
      signed EngagementScope.

Any lookup satisfying neither (a) nor (b) raises PersonScopeRequiredError (HTTP 403
SCOPE_REQUIRED) and writes an immutable BLOCKED audit row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from redloop.audit import AuditLogger


AUTH_BASIS_SELF_LOOKUP = "self_lookup"
AUTH_BASIS_ENGAGEMENT = "engagement_authorized"
AUTH_BASIS_DENIED = "denied_scope_required"

ERROR_CODE_SCOPE_REQUIRED = "SCOPE_REQUIRED"
HTTP_STATUS_FORBIDDEN = 403


def normalize_person_identifier(target: str, identifier_type: str = "auto") -> Tuple[str, str]:
    """Normalize an email, phone, or username into canonical form and return (norm_target, detected_type)."""
    raw = (target or "").strip()
    if not raw:
        return "", "unknown"

    # Strip surrounding quotes
    if len(raw) >= 2 and raw[0] in ("'", '"', "`") and raw[-1] == raw[0]:
        raw = raw[1:-1].strip()

    id_type = (identifier_type or "auto").lower().strip()

    if id_type == "email" or (id_type == "auto" and "@" in raw and "." in raw.split("@")[-1]):
        return raw.lower(), "email"

    # Phone detection: starts with + or digits/hyphens/parens with >=7 digits
    digits_only = re.sub(r"[^\d+]", "", raw)
    digit_count = len(re.sub(r"\D", "", raw))
    if id_type == "phone" or (
        id_type == "auto"
        and digit_count >= 7
        and re.match(r"^\+?[\d\s\-\(\)\.]{7,20}$", raw)
    ):
        if not digits_only.startswith("+") and digit_count >= 10:
            digits_only = "+" + digits_only
        return digits_only, "phone"

    # Username: strip leading @ if present
    clean_handle = raw.lstrip("@").strip().lower()
    return clean_handle, "username"


@dataclass(frozen=True)
class PersonScopeDecision:
    """Result of evaluating the L.0 person-identifying lookup gate."""

    allowed: bool
    target: str
    normalized_target: str
    identifier_type: str
    entry_point: str
    authorization_basis: str
    status_code: int
    error_code: Optional[str] = None
    why_this_result_is_shown: str = ""
    audit_event_recorded: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "allowed": self.allowed,
            "target": self.target,
            "normalized_target": self.normalized_target,
            "identifier_type": self.identifier_type,
            "entry_point": self.entry_point,
            "authorization_basis": self.authorization_basis,
            "status_code": self.status_code,
            "why_this_result_is_shown": self.why_this_result_is_shown,
            "audit_event_recorded": self.audit_event_recorded,
            "timestamp": self.timestamp,
        }
        if self.error_code:
            payload["error_code"] = self.error_code
        return payload


class PersonScopeRequiredError(Exception):
    """Raised when an email/phone/username lookup fails both (a) self-lookup and (b) active EngagementScope."""

    def __init__(self, decision: PersonScopeDecision, message: Optional[str] = None) -> None:
        self.decision = decision
        self.status_code = HTTP_STATUS_FORBIDDEN
        self.error_code = ERROR_CODE_SCOPE_REQUIRED
        self.target = decision.target
        self.identifier_type = decision.identifier_type
        self.entry_point = decision.entry_point
        msg = message or (
            f"403 {ERROR_CODE_SCOPE_REQUIRED}: Person-identifying lookup for "
            f"{decision.identifier_type} '{decision.target}' via {decision.entry_point} is blocked. "
            f"Target is neither (a) the operator's own verified identifier nor "
            f"(b) listed in an active, signed EngagementScope."
        )
        self.message = msg
        super().__init__(msg)

    def to_response_dict(self) -> Dict[str, Any]:
        return {
            "status": "error",
            "http_status": self.status_code,
            "error_code": self.error_code,
            "message": self.message,
            "target": self.target,
            "identifier_type": self.identifier_type,
            "entry_point": self.entry_point,
            "authorization_basis": self.decision.authorization_basis,
            "why_this_result_is_shown": self.decision.why_this_result_is_shown,
            "audit_logged": self.decision.audit_event_recorded,
        }


class PersonScopeGate:
    """Single mandatory choke point for person-identifying lookups (email, phone, username)."""

    def __init__(
        self,
        operator_identifiers: Optional[Iterable[str]] = None,
        scope_guard: Any = None,
        scope_manager: Any = None,
        engagement_scope: Optional[Iterable[str]] = None,
        engagement_signed: bool = True,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.scope_manager = scope_manager
        self.engagement_signed = engagement_signed
        self.audit_logger = audit_logger

        # Load operator's own verified identifiers
        raw_ops: Set[str] = set()
        if operator_identifiers:
            for item in operator_identifiers:
                if item and str(item).strip():
                    norm, _ = normalize_person_identifier(str(item))
                    if norm:
                        raw_ops.add(norm)
        env_ops = os.environ.get("REDLOOP_OPERATOR_IDENTIFIERS", "")
        if env_ops:
            for part in env_ops.split(","):
                if part.strip():
                    norm, _ = normalize_person_identifier(part.strip())
                    if norm:
                        raw_ops.add(norm)
        self.operator_identifiers: Set[str] = raw_ops

        # Explicit signed engagement target list (if provided directly)
        raw_eng: Set[str] = set()
        if engagement_scope:
            for item in engagement_scope:
                if item and str(item).strip():
                    norm, _ = normalize_person_identifier(str(item))
                    if norm:
                        raw_eng.add(norm)
        self.engagement_targets: Set[str] = raw_eng

    def _is_in_signed_engagement(self, norm_target: str, id_type: str) -> bool:
        """Check whether norm_target is covered by an active, signed EngagementScope."""
        if not self.engagement_signed:
            return False

        # 1. Direct match in explicit signed engagement targets
        if norm_target in self.engagement_targets:
            return True

        # For email addresses, check if the exact email or wildcard @domain is in engagement_targets
        if id_type == "email" and "@" in norm_target:
            _, domain = norm_target.rsplit("@", 1)
            if f"*@{domain}" in self.engagement_targets or domain in self.engagement_targets:
                return True

        # 2. Check via AssessmentScopeGuard if attached
        if self.scope_guard is not None:
            try:
                if hasattr(self.scope_guard, "is_target_scoped") and self.scope_guard.is_target_scoped(norm_target):
                    return True
                if id_type == "email" and "@" in norm_target:
                    _, domain = norm_target.rsplit("@", 1)
                    if hasattr(self.scope_guard, "is_target_scoped") and self.scope_guard.is_target_scoped(domain):
                        return True
            except Exception:
                pass

        # 3. Check via ScopeManager if attached
        if self.scope_manager is not None:
            try:
                if hasattr(self.scope_manager, "is_within_window") and not self.scope_manager.is_within_window():
                    return False
                scope_obj = getattr(self.scope_manager, "scope", None)
                if scope_obj and hasattr(scope_obj, "targets"):
                    for entry in scope_obj.targets:
                        entry_dom = (getattr(entry, "domain", None) or "").strip().lower()
                        entry_label = (getattr(entry, "label", None) or "").strip().lower()
                        if entry_dom and (entry_dom == norm_target or entry_label == norm_target):
                            return True
                        if id_type == "email" and "@" in norm_target:
                            _, domain = norm_target.rsplit("@", 1)
                            if entry_dom == domain or entry_dom == f"*.{domain}":
                                return True
            except Exception:
                pass

        return False

    def _record_audit(
        self,
        target: str,
        id_type: str,
        entry_point: str,
        status: str,
        basis: str,
        reason: str,
    ) -> bool:
        """Write an immutable audit entry to AuditLogger."""
        if self.audit_logger is None:
            return True
        try:
            self.audit_logger.log(
                target=str(target),
                action=f"person_osint:{id_type}",
                category=f"person_scope_gate:{entry_point}",
                status=status,
                details={
                    "identifier_type": id_type,
                    "entry_point": entry_point,
                    "authorization_basis": basis,
                    "why_this_result_is_shown": reason,
                },
            )
            return True
        except Exception:
            return False

    def evaluate(
        self,
        target: str,
        identifier_type: str = "auto",
        entry_point: str = "rest",
        operator_identifier: Optional[str] = None,
    ) -> PersonScopeDecision:
        """Evaluate whether a person-identifying lookup is permitted without raising."""
        norm_target, detected_type = normalize_person_identifier(target, identifier_type)
        entry_pt = (entry_point or "rest").lower().strip()

        if not norm_target:
            reason = "Denied: Empty or malformed person-identifying target."
            self._record_audit(target, detected_type, entry_pt, "BLOCKED", AUTH_BASIS_DENIED, reason)
            return PersonScopeDecision(
                allowed=False,
                target=target,
                normalized_target=norm_target,
                identifier_type=detected_type,
                entry_point=entry_pt,
                authorization_basis=AUTH_BASIS_DENIED,
                status_code=HTTP_STATUS_FORBIDDEN,
                error_code=ERROR_CODE_SCOPE_REQUIRED,
                why_this_result_is_shown=reason,
            )

        # Check (a): Self-lookup against operator's verified identifier(s)
        op_set = set(self.operator_identifiers)
        if operator_identifier:
            norm_op, _ = normalize_person_identifier(operator_identifier, detected_type)
            if norm_op:
                op_set.add(norm_op)

        if norm_target in op_set:
            ui_reason = (
                f"Why this result is shown: Self-lookup authorized (target '{norm_target}' "
                f"matches operator's verified {detected_type} identifier; logged to audit ledger)."
            )
            self._record_audit(
                norm_target,
                detected_type,
                entry_pt,
                "ALLOWED_SELF_LOOKUP",
                AUTH_BASIS_SELF_LOOKUP,
                ui_reason,
            )
            return PersonScopeDecision(
                allowed=True,
                target=target,
                normalized_target=norm_target,
                identifier_type=detected_type,
                entry_point=entry_pt,
                authorization_basis=AUTH_BASIS_SELF_LOOKUP,
                status_code=200,
                why_this_result_is_shown=ui_reason,
            )

        # Check (b): Listed inside active, signed EngagementScope
        if self._is_in_signed_engagement(norm_target, detected_type):
            ui_reason = (
                f"Why this result is shown: Engagement-authorized lookup (target '{norm_target}' "
                f"is explicitly covered by the active, signed EngagementScope)."
            )
            self._record_audit(
                norm_target,
                detected_type,
                entry_pt,
                "ALLOWED_ENGAGEMENT_SCOPE",
                AUTH_BASIS_ENGAGEMENT,
                ui_reason,
            )
            return PersonScopeDecision(
                allowed=True,
                target=target,
                normalized_target=norm_target,
                identifier_type=detected_type,
                entry_point=entry_pt,
                authorization_basis=AUTH_BASIS_ENGAGEMENT,
                status_code=200,
                why_this_result_is_shown=ui_reason,
            )

        # Neither (a) nor (b) -> 403 SCOPE_REQUIRED
        deny_reason = (
            f"Blocked (403 SCOPE_REQUIRED): Target '{norm_target}' ({detected_type}) is neither "
            f"(a) the operator's verified identifier nor (b) inside an active, signed EngagementScope."
        )
        self._record_audit(
            norm_target,
            detected_type,
            entry_pt,
            "BLOCKED_SCOPE_REQUIRED",
            AUTH_BASIS_DENIED,
            deny_reason,
        )
        return PersonScopeDecision(
            allowed=False,
            target=target,
            normalized_target=norm_target,
            identifier_type=detected_type,
            entry_point=entry_pt,
            authorization_basis=AUTH_BASIS_DENIED,
            status_code=HTTP_STATUS_FORBIDDEN,
            error_code=ERROR_CODE_SCOPE_REQUIRED,
            why_this_result_is_shown=deny_reason,
        )

    def enforce(
        self,
        target: str,
        identifier_type: str = "auto",
        entry_point: str = "rest",
        operator_identifier: Optional[str] = None,
    ) -> PersonScopeDecision:
        """Enforce the L.0 gate; raises PersonScopeRequiredError (403) if not authorized."""
        decision = self.evaluate(
            target=target,
            identifier_type=identifier_type,
            entry_point=entry_point,
            operator_identifier=operator_identifier,
        )
        if not decision.allowed:
            raise PersonScopeRequiredError(decision)
        return decision


def handle_rest_person_lookup(
    gate: PersonScopeGate,
    target: str,
    identifier_type: str = "auto",
    operator_identifier: Optional[str] = None,
    lookup_fn: Optional[ Any ] = None,
) -> Tuple[int, Dict[str, Any]]:
    """REST entry-point wrapper enforcing L.0 PersonScopeGate.

    Returns (http_status_code, response_dict).
    """
    try:
        decision = gate.enforce(
            target=target,
            identifier_type=identifier_type,
            entry_point="rest",
            operator_identifier=operator_identifier,
        )
    except PersonScopeRequiredError as exc:
        return exc.status_code, exc.to_response_dict()

    data = lookup_fn(decision.normalized_target, decision.identifier_type) if callable(lookup_fn) else {}
    return 200, {
        "status": "ok",
        "http_status": 200,
        "target": decision.normalized_target,
        "identifier_type": decision.identifier_type,
        "entry_point": "rest",
        "authorization_basis": decision.authorization_basis,
        "why_this_result_is_shown": decision.why_this_result_is_shown,
        "result": data,
    }


def handle_chat_person_lookup(
    gate: PersonScopeGate,
    target: str,
    identifier_type: str = "auto",
    operator_identifier: Optional[str] = None,
    lookup_fn: Optional[ Any ] = None,
) -> Dict[str, Any]:
    """Chat / Copilot entry-point wrapper enforcing L.0 PersonScopeGate."""
    try:
        decision = gate.enforce(
            target=target,
            identifier_type=identifier_type,
            entry_point="chat",
            operator_identifier=operator_identifier,
        )
    except PersonScopeRequiredError as exc:
        return exc.to_response_dict()

    data = lookup_fn(decision.normalized_target, decision.identifier_type) if callable(lookup_fn) else {}
    return {
        "status": "ok",
        "http_status": 200,
        "target": decision.normalized_target,
        "identifier_type": decision.identifier_type,
        "entry_point": "chat",
        "authorization_basis": decision.authorization_basis,
        "why_this_result_is_shown": decision.why_this_result_is_shown,
        "ui_banner": f"[{decision.authorization_basis.upper()}] {decision.why_this_result_is_shown}",
        "result": data,
    }


def handle_mcp_person_lookup(
    gate: PersonScopeGate,
    target: str,
    identifier_type: str = "auto",
    operator_identifier: Optional[str] = None,
    lookup_fn: Optional[ Any ] = None,
) -> Dict[str, Any]:
    """MCP tool entry-point wrapper enforcing L.0 PersonScopeGate."""
    try:
        decision = gate.enforce(
            target=target,
            identifier_type=identifier_type,
            entry_point="mcp",
            operator_identifier=operator_identifier,
        )
    except PersonScopeRequiredError as exc:
        return exc.to_response_dict()

    data = lookup_fn(decision.normalized_target, decision.identifier_type) if callable(lookup_fn) else {}
    return {
        "status": "ok",
        "http_status": 200,
        "target": decision.normalized_target,
        "identifier_type": decision.identifier_type,
        "entry_point": "mcp",
        "authorization_basis": decision.authorization_basis,
        "why_this_result_is_shown": decision.why_this_result_is_shown,
        "result": data,
    }

