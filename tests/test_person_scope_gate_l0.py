"""Unit & Integration Tests for Gate L.0: Person-Identifying OSINT Scope Gate.

Verifies:
1. Every email/phone/username lookup passes ONE of:
   (a) target == operator's own verified identifier (self-lookup, logged), OR
   (b) target is listed inside the currently active, signed EngagementScope.
2. Any lookup satisfying neither (a) nor (b) returns 403 SCOPE_REQUIRED and writes
   an audit row across REST, Chat, and MCP entry points.
3. UI banner / response logs 'why_this_result_is_shown' (self_lookup vs engagement_authorized).
4. >= 30 tests proving (a)/(b) enforced on all 3 entry points with 0 bypass.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List
import pytest

from redloop.assessment.person_scope_gate import (
    AUTH_BASIS_DENIED,
    AUTH_BASIS_ENGAGEMENT,
    AUTH_BASIS_SELF_LOOKUP,
    ERROR_CODE_SCOPE_REQUIRED,
    HTTP_STATUS_FORBIDDEN,
    PersonScopeGate,
    PersonScopeRequiredError,
    handle_chat_person_lookup,
    handle_mcp_person_lookup,
    handle_rest_person_lookup,
    normalize_person_identifier,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.connectors.mcp_server import RedloopMCPServer
from redloop.scope import ScopeFile, ScopeEntry, ScopeManager


class InMemoryAuditRecorder:
    """In-memory audit ledger spy verifying every allowed and blocked lookup is recorded."""

    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    def log(
        self,
        target: str,
        action: str,
        category: str,
        status: str,
        details: Dict[str, Any] | None = None,
    ) -> None:
        self.rows.append(
            {
                "target": target,
                "action": action,
                "category": category,
                "status": status,
                "details": details or {},
            }
        )


# ==============================================================================
# 1. Identifier Normalization Tests
# ==============================================================================

@pytest.mark.parametrize(
    "raw_input,id_type,expected_norm,expected_type",
    [
        ("  Operator@RedLoop.io ", "email", "operator@redloop.io", "email"),
        ("'alice.sec@corp.example.com'", "auto", "alice.sec@corp.example.com", "email"),
        ("+1 (415) 555-0199", "phone", "+14155550199", "phone"),
        ("+44 20 7946 0958", "auto", "+442079460958", "phone"),
        ("@Shadow_Broker_99", "username", "shadow_broker_99", "username"),
        ("'redteam_operator'", "auto", "redteam_operator", "username"),
    ],
)
def test_normalize_person_identifier(
    raw_input: str, id_type: str, expected_norm: str, expected_type: str
) -> None:
    norm, det_type = normalize_person_identifier(raw_input, id_type)
    assert norm == expected_norm
    assert det_type == expected_type


# ==============================================================================
# 2. Condition (a): Self-Lookup Across REST, Chat, and MCP (9 Tests)
# ==============================================================================

@pytest.mark.parametrize(
    "target,id_type",
    [
        ("rabi.operator@redloop.sec", "email"),
        ("+14155550100", "phone"),
        ("rabi_sec_ops", "username"),
    ],
)
def test_self_lookup_allowed_on_rest(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["rabi.operator@redloop.sec", "+1 (415) 555-0100", "@rabi_sec_ops"],
        engagement_scope=[],
        audit_logger=audit,  # type: ignore[arg-type]
    )
    status_code, body = handle_rest_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=lambda t, tp: {"checked": t}
    )
    assert status_code == 200
    assert body["authorization_basis"] == AUTH_BASIS_SELF_LOOKUP
    assert "Self-lookup authorized" in body["why_this_result_is_shown"]
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "ALLOWED_SELF_LOOKUP"
    assert audit.rows[0]["category"] == "person_scope_gate:rest"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("rabi.operator@redloop.sec", "email"),
        ("+14155550100", "phone"),
        ("rabi_sec_ops", "username"),
    ],
)
def test_self_lookup_allowed_on_chat(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["rabi.operator@redloop.sec", "+14155550100", "rabi_sec_ops"],
        engagement_scope=[],
        audit_logger=audit,  # type: ignore[arg-type]
    )
    body = handle_chat_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=lambda t, tp: {"checked": t}
    )
    assert body["http_status"] == 200
    assert body["authorization_basis"] == AUTH_BASIS_SELF_LOOKUP
    assert "[SELF_LOOKUP]" in body["ui_banner"]
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "ALLOWED_SELF_LOOKUP"
    assert audit.rows[0]["category"] == "person_scope_gate:chat"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("rabi.operator@redloop.sec", "email"),
        ("+14155550100", "phone"),
        ("rabi_sec_ops", "username"),
    ],
)
def test_self_lookup_allowed_on_mcp_server(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["rabi.operator@redloop.sec", "+14155550100", "rabi_sec_ops"],
        engagement_scope=[],
        audit_logger=audit,  # type: ignore[arg-type]
    )
    mcp_srv = RedloopMCPServer(person_scope_gate=gate, audit_ledger=audit)  # type: ignore[arg-type]
    body = handle_mcp_person_lookup(
        mcp_srv.person_scope_gate,
        target=target,
        identifier_type=id_type,
        lookup_fn=lambda t, tp: {"checked": t},
    )
    assert body["http_status"] == 200
    assert body["authorization_basis"] == AUTH_BASIS_SELF_LOOKUP
    assert "Self-lookup authorized" in body["why_this_result_is_shown"]
    assert any(r["status"] == "ALLOWED_SELF_LOOKUP" for r in audit.rows)


# ==============================================================================
# 3. Condition (b): Signed EngagementScope Across REST, Chat, and MCP (9 Tests)
# ==============================================================================

@pytest.mark.parametrize(
    "target,id_type",
    [
        ("ceo@scoped-client.org", "email"),
        ("+18005550142", "phone"),
        ("scoped_exec_handle", "username"),
    ],
)
def test_engagement_authorized_on_rest(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=[],
        engagement_scope=["scoped-client.org", "+18005550142", "scoped_exec_handle"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    status_code, body = handle_rest_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=lambda t, tp: {"checked": t}
    )
    assert status_code == 200
    assert body["authorization_basis"] == AUTH_BASIS_ENGAGEMENT
    assert "Engagement-authorized" in body["why_this_result_is_shown"]
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "ALLOWED_ENGAGEMENT_SCOPE"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("dev@scoped-client.org", "email"),
        ("+18005550142", "phone"),
        ("scoped_exec_handle", "username"),
    ],
)
def test_engagement_authorized_on_chat(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=[],
        engagement_scope=["*@scoped-client.org", "+18005550142", "scoped_exec_handle"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    body = handle_chat_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=lambda t, tp: {"checked": t}
    )
    assert body["http_status"] == 200
    assert body["authorization_basis"] == AUTH_BASIS_ENGAGEMENT
    assert "[ENGAGEMENT_AUTHORIZED]" in body["ui_banner"]
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "ALLOWED_ENGAGEMENT_SCOPE"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("security@scoped-client.org", "email"),
        ("+18005550142", "phone"),
        ("scoped_exec_handle", "username"),
    ],
)
def test_engagement_authorized_on_mcp_server(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=[],
        engagement_scope=["scoped-client.org", "+18005550142", "scoped_exec_handle"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    mcp_srv = RedloopMCPServer(person_scope_gate=gate, audit_ledger=audit)  # type: ignore[arg-type]
    body = handle_mcp_person_lookup(
        mcp_srv.person_scope_gate,
        target=target,
        identifier_type=id_type,
        lookup_fn=lambda t, tp: {"checked": t},
    )
    assert body["http_status"] == 200
    assert body["authorization_basis"] == AUTH_BASIS_ENGAGEMENT
    assert "Engagement-authorized" in body["why_this_result_is_shown"]
    assert any(r["status"] == "ALLOWED_ENGAGEMENT_SCOPE" for r in audit.rows)


# ==============================================================================
# 4. Unauthorized Denied (403 SCOPE_REQUIRED + Audit Row) Across All 3 Entry Points (12 Tests)
# ==============================================================================

@pytest.mark.parametrize(
    "target,id_type",
    [
        ("stranger@unscoped-gmail.com", "email"),
        ("victim@other-company.net", "email"),
        ("+12025550191", "phone"),
        ("random_citizen_handle", "username"),
    ],
)
def test_unauthorized_blocked_403_on_rest(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["operator@redloop.sec"],
        engagement_scope=["scoped-client.org"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    called = False

    def should_never_run(t: str, tp: str) -> Dict[str, Any]:
        nonlocal called
        called = True
        return {}

    status_code, body = handle_rest_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=should_never_run
    )
    assert called is False, "Underlying OSINT module must NEVER be called on 403 block"
    assert status_code == HTTP_STATUS_FORBIDDEN
    assert body["http_status"] == 403
    assert body["error_code"] == ERROR_CODE_SCOPE_REQUIRED
    assert body["authorization_basis"] == AUTH_BASIS_DENIED
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "BLOCKED_SCOPE_REQUIRED"
    assert audit.rows[0]["category"] == "person_scope_gate:rest"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("stranger@unscoped-gmail.com", "email"),
        ("ceo@rival-corp.io", "email"),
        ("+447700900077", "phone"),
        ("unscoped_github_user", "username"),
    ],
)
def test_unauthorized_blocked_403_on_chat(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["operator@redloop.sec"],
        engagement_scope=["scoped-client.org"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    called = False

    def should_never_run(t: str, tp: str) -> Dict[str, Any]:
        nonlocal called
        called = True
        return {}

    body = handle_chat_person_lookup(
        gate, target=target, identifier_type=id_type, lookup_fn=should_never_run
    )
    assert called is False
    assert body["http_status"] == 403
    assert body["error_code"] == ERROR_CODE_SCOPE_REQUIRED
    assert len(audit.rows) == 1
    assert audit.rows[0]["status"] == "BLOCKED_SCOPE_REQUIRED"
    assert audit.rows[0]["category"] == "person_scope_gate:chat"


@pytest.mark.parametrize(
    "target,id_type",
    [
        ("stranger@unscoped-gmail.com", "email"),
        ("admin@untrusted.org", "email"),
        ("+13105550188", "phone"),
        ("out_of_scope_handle", "username"),
    ],
)
def test_unauthorized_blocked_403_on_mcp(target: str, id_type: str) -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["operator@redloop.sec"],
        engagement_scope=["scoped-client.org"],
        engagement_signed=True,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    mcp_srv = RedloopMCPServer(person_scope_gate=gate, audit_ledger=audit)  # type: ignore[arg-type]
    called = False

    def should_never_run(t: str, tp: str) -> Dict[str, Any]:
        nonlocal called
        called = True
        return {}

    body = handle_mcp_person_lookup(
        mcp_srv.person_scope_gate,
        target=target,
        identifier_type=id_type,
        lookup_fn=should_never_run,
    )
    assert called is False
    assert body["http_status"] == 403
    assert body["error_code"] == ERROR_CODE_SCOPE_REQUIRED
    assert any(r["status"] == "BLOCKED_SCOPE_REQUIRED" for r in audit.rows)


# ==============================================================================
# 5. Edge Cases: Unsigned Scope, Expired Scope, Empty Target, ScopeManager Binding
# ==============================================================================

def test_unsigned_engagement_scope_rejects_target_with_403() -> None:
    """Even if a target is listed in engagement_scope, if engagement_signed=False it must fail."""
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=[],
        engagement_scope=["ceo@scoped-client.org"],
        engagement_signed=False,
        audit_logger=audit,  # type: ignore[arg-type]
    )
    with pytest.raises(PersonScopeRequiredError) as exc_info:
        gate.enforce("ceo@scoped-client.org", identifier_type="email", entry_point="rest")
    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "SCOPE_REQUIRED"
    assert audit.rows[0]["status"] == "BLOCKED_SCOPE_REQUIRED"


def test_empty_target_rejected_with_403_and_logged() -> None:
    audit = InMemoryAuditRecorder()
    gate = PersonScopeGate(
        operator_identifiers=["operator@redloop.sec"],
        audit_logger=audit,  # type: ignore[arg-type]
    )
    status_code, body = handle_rest_person_lookup(gate, target="   ", identifier_type="email")
    assert status_code == 403
    assert body["error_code"] == "SCOPE_REQUIRED"
    assert len(audit.rows) == 1


def test_scope_manager_integration_with_person_scope_gate() -> None:
    """Verify PersonScopeGate integrates with ScopeManager + AssessmentScopeGuard."""
    today = date.today()
    doc = ScopeFile(
        engagement_id="ENG-2026-L0",
        operator="rabi",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        targets=[
            ScopeEntry(
                domain="authorized-bounty.com",
                authorized_from=today - timedelta(days=1),
                authorized_until=today + timedelta(days=7),
                allowed_actions=["recon", "scan"],
                label="authorized_handle_01",
            )
        ],
        signature="valid-sig",
    )
    sm = ScopeManager.__new__(ScopeManager)
    sm.scope = doc
    sm.is_within_window = lambda: True  # type: ignore[method-assign]
    guard = AssessmentScopeGuard(sm)
    audit = InMemoryAuditRecorder()

    gate = PersonScopeGate(
        operator_identifiers=[],
        scope_guard=guard,
        scope_manager=sm,
        audit_logger=audit,  # type: ignore[arg-type]
    )

    # In-scope email under authorized-bounty.com
    dec1 = gate.enforce("cto@authorized-bounty.com", identifier_type="email", entry_point="rest")
    assert dec1.allowed is True
    assert dec1.authorization_basis == AUTH_BASIS_ENGAGEMENT

    # Out-of-scope email
    with pytest.raises(PersonScopeRequiredError):
        gate.enforce("cto@unauthorized-domain.com", identifier_type="email", entry_point="rest")
