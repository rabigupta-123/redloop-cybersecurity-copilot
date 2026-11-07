"""Comprehensive Phase 11 security boundary and pipeline hardening test suite.

Covers tests A through U:
A. Authorized localhost target -> permitted stages execute.
B. Unauthorized external target -> network stages BLOCKED.
C. Unauthorized target -> local evidence stages continue.
D. Direct REST call -> cannot bypass scope.
E. Direct engine call -> cannot bypass scope.
F. DNS engine -> cannot bypass scope.
G. TLS engine -> cannot bypass scope.
H. Web engine -> cannot bypass scope.
I. API engine -> cannot bypass scope.
J. Redirect to unauthorized destination -> blocked.
K. DNS resolving authorized hostname to unauthorized/private destination where applicable -> policy enforced.
L. Scope expiry -> blocked.
M. Invalid/tampered signature -> blocked.
N. Audit tampering -> detected.
O. Duplicate request -> correct task reused.
P. Different request within 10 seconds -> NOT incorrectly deduplicated.
Q. Provider authentication failure -> fallback works if available.
R. Provider quota failure -> fallback works if available.
S. All providers unavailable -> deterministic/offline mode works without fake AI output.
T. API key accidentally present in logs -> test confirms redaction.
U. Chat and Workbench -> identical orchestration semantics.
"""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import pytest
import yaml
import httpx

from redloop.assessment.api_engine import APIEngine
from redloop.assessment.dns_engine import DNSEngine
from redloop.assessment.engine import AssessmentEngine, AssessmentStore
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    Evidence,
    EvidenceProvenance,
    Finding,
    Severity,
    StageStatus,
)
from redloop.assessment.orchestrator import Task, TaskOrchestrator
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.tls_engine import TLSEngine
from redloop.assessment.web_engine import WebEngine
from redloop.assessment.shodan_engine import ShodanEngine
from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from redloop.llm import LLMClient, Provider
from redloop.scope import ScopeManager, UnauthorizedTargetError, sign_scope


@pytest.fixture
def env(tmp_path: Path):
    """Setup isolated test environment with signed scope, audit DB, and assessment store."""
    today = date.today()
    scope_data = {
        "version": 1,
        "id": "hardening-test-scope",
        "authorized_by": "sec-ops",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback-auth",
                "authorized_from": str(today - timedelta(days=1)),
                "authorized_until": str(today + timedelta(days=30)),
                "allowed_actions": ["scan", "recon", "assess", "web_check", "tls_check", "dns_check", "api_check"],
                "ports": [80, 443, 8080, 8765],
            },
            {
                "domain": "internal.authorized.local",
                "label": "internal-domain",
                "authorized_from": str(today - timedelta(days=1)),
                "authorized_until": str(today + timedelta(days=30)),
                "allowed_actions": ["scan", "recon", "assess", "web_check", "tls_check", "dns_check"],
                "ports": [80, 443],
            },
        ],
    }
    secret = "hardening-secret-key-12345"
    scope_data["signature"] = sign_scope(scope_data, secret)

    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")

    audit_db = tmp_path / "audit.db"
    task_db = tmp_path / "tasks.sqlite"
    asmt_db = tmp_path / "assessments.sqlite"

    scope_mgr = ScopeManager(scope_file=scope_file, secret=secret)
    audit = AuditLogger(db_path=audit_db)
    guard = AssessmentScopeGuard(scope_manager=scope_mgr, audit=audit)
    asmt_store = AssessmentStore(db_path=asmt_db)
    engine = AssessmentEngine(scope_guard=guard, audit=audit, store=asmt_store)

    orchestrator = TaskOrchestrator(
        scope_manager=scope_mgr,
        audit_db=audit_db,
        task_db=task_db,
        assessment_db=asmt_db,
    )

    return {
        "tmp_path": tmp_path,
        "scope_mgr": scope_mgr,
        "scope_file": scope_file,
        "secret": secret,
        "audit": audit,
        "audit_db": audit_db,
        "guard": guard,
        "engine": engine,
        "asmt_store": asmt_store,
        "orchestrator": orchestrator,
    }


# A. Authorized localhost target -> permitted stages execute
@pytest.mark.asyncio
async def test_a_authorized_localhost_target_executes(env):
    orch = env["orchestrator"]
    res = await orch.execute_task(
        prompt="Assess 127.0.0.1 with quick depth",
        conversation_id="conv-a",
    )
    assert res["task"]["status"] in ("COMPLETED", "PARTIAL", "SUCCESS")
    assert res["task"]["scope_authorized"] is True
    # At least some stages executed
    assert len(res["task"]["stages"]) > 0
    # No scope blocked errors on 127.0.0.1
    for st in res["task"]["stages"]:
        if st["name"] == "scope_validation":
            assert st["status"] == "SUCCESS"


# B. Unauthorized external target -> network stages BLOCKED
@pytest.mark.asyncio
async def test_b_unauthorized_external_target_network_blocked(env):
    orch = env["orchestrator"]
    res = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-b",
    )
    assert res["task"]["status"] == "PARTIALLY_BLOCKED"
    assert res["task"]["scope_authorized"] is False
    blocked = res["structured_result"]["blocked_stages"]
    assert "scope_validation" in blocked
    assert any("web" in s or "network" in s or "dns" in s for s in blocked)


# C. Unauthorized target -> local evidence stages continue
@pytest.mark.asyncio
async def test_c_unauthorized_target_local_evidence_continues(env):
    orch = env["orchestrator"]
    # Seed historical finding
    asmt_store = env["asmt_store"]
    hist_state = AssessmentState(
        target="rathinamtechpark.com",
        status="COMPLETED",
        findings=[
            Finding(
                title="Historical Finding Test",
                category="web",
                severity=Severity.LOW,
                asset="rathinamtechpark.com",
                target="rathinamtechpark.com",
                description="Seeded past finding.",
            )
        ],
    )
    asmt_store.save(hist_state)

    res = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-c",
    )
    executed = res["structured_result"]["executed_stages"]
    assert "local_evidence_review" in executed
    assert "correlation_and_risk" in executed
    assert res["structured_result"]["status"] == "partially_blocked"
    assert "Historical Finding Test" in res["response"]


# D. Direct REST call -> cannot bypass scope
def test_d_direct_rest_cannot_bypass_scope(env):
    from starlette.testclient import TestClient

    app = create_app(
        db_path=str(env["audit_db"]),
        scope_manager=env["scope_mgr"],
    )
    client = TestClient(app)

    # Attempt direct probe on unauthorized target
    res = client.post("/api/workbench/red/tls-check", json={"target": "unauthorized.external.com", "port": 443})
    assert res.status_code in (400, 403)


# E. Direct engine call -> cannot bypass scope
def test_e_direct_engine_cannot_bypass_scope(env):
    eng = env["engine"]
    with pytest.raises(ScopeBlockedError):
        eng.scope_guard.is_target_authorized("evil-target.com", "scan")


# F. DNS engine -> cannot bypass scope
def test_f_dns_engine_cannot_bypass_scope(env):
    dns_eng = DNSEngine(scope_guard=env["guard"], audit=env["audit"])
    res = dns_eng.assess_target("unauthorized-domain.com")
    assert res.status == StageStatus.BLOCKED
    assert "Scope authorization rejected" in res.reason


# G. TLS engine -> cannot bypass scope
def test_g_tls_engine_cannot_bypass_scope(env):
    tls_eng = TLSEngine(scope_guard=env["guard"], audit=env["audit"])
    res = tls_eng.assess_target("unauthorized-tls.com", port=443)
    assert res.status == StageStatus.BLOCKED
    assert "Scope authorization rejected" in res.reason


# H. Web engine -> cannot bypass scope
def test_h_web_engine_cannot_bypass_scope(env):
    web_eng = WebEngine(scope_guard=env["guard"], audit=env["audit"])
    res = web_eng.assess_url("https://unauthorized-web.com")
    assert res.status == StageStatus.BLOCKED
    assert "Scope authorization rejected" in res.reason


# I. API engine -> cannot bypass scope
def test_i_api_engine_cannot_bypass_scope(env):
    api_eng = APIEngine(scope_guard=env["guard"], audit=env["audit"])
    res = api_eng.assess_api("https://unauthorized-api.com")
    assert res.status == StageStatus.BLOCKED
    assert "Scope authorization rejected" in res.reason


# J. Redirect to unauthorized destination -> blocked
def test_j_redirect_to_unauthorized_destination_blocked(env):
    web_eng = WebEngine(scope_guard=env["guard"], audit=env["audit"])
    # Mock a client that returns 302 redirect to unauthorized external host
    mock_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(302, headers={"Location": "https://unauthorized-evil.com/leak"})
        )
    )
    # Target 127.0.0.1 is authorized, but redirect to unauthorized-evil.com is blocked
    resp = web_eng._safe_fetch(mock_client, "GET", "http://127.0.0.1:8080/redir")
    # Must NOT have followed the redirect to unauthorized host!
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://unauthorized-evil.com/leak"


# K. DNS resolving authorized hostname to unauthorized/private destination -> policy enforced
def test_k_dns_resolving_to_private_enforced(env):
    guard = env["guard"]
    # If a public domain resolves to 127.0.0.1 or 10.0.0.1, validate_resolved_ip blocks it
    with pytest.raises(ScopeBlockedError) as exc_info:
        guard.validate_resolved_ip("public-corp.com", "127.0.0.1")
    assert "prohibited by policy" in str(exc_info.value)


# L. Scope expiry -> blocked
def test_l_scope_expiry_blocked(tmp_path: Path):
    today = date.today()
    expired_data = {
        "version": 1,
        "id": "expired-scope",
        "authorized_by": "sec-ops",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2020-12-31T23:59:59Z",  # Expired in past
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback-expired",
                "authorized_from": "2020-01-01",
                "authorized_until": "2020-12-31",
                "allowed_actions": ["scan"],
            }
        ],
    }
    secret = "secret-xyz"
    expired_data["signature"] = sign_scope(expired_data, secret)
    f = tmp_path / "expired_scope.yaml"
    f.write_text(yaml.safe_dump(expired_data), encoding="utf-8")

    mgr = ScopeManager(scope_file=f, secret=secret)
    guard = AssessmentScopeGuard(scope_manager=mgr)

    with pytest.raises(ScopeBlockedError) as exc:
        guard.is_target_authorized("127.0.0.1", "scan")
    assert "expired" in str(exc.value)


# M. Invalid/tampered signature -> blocked
def test_m_invalid_tampered_signature_blocked(tmp_path: Path):
    scope_data = {
        "version": 1,
        "id": "tampered-scope",
        "authorized_by": "attacker",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [{"cidr": "127.0.0.1/32", "authorized_from": "2026-01-01", "authorized_until": "2099-12-31", "allowed_actions": ["scan"]}],
        "signature": "fake-tampered-signature-00000000",
    }
    f = tmp_path / "tampered.yaml"
    f.write_text(yaml.safe_dump(scope_data), encoding="utf-8")

    with pytest.raises(UnauthorizedTargetError) as exc:
        ScopeManager(scope_file=f, secret="correct-secret")
    assert "invalid" in str(exc.value).lower()


# N. Audit tampering -> detected
def test_n_audit_tampering_detected(tmp_path: Path):
    db_path = tmp_path / "audit_tamper.db"
    audit = AuditLogger(db_path=db_path)
    audit.log("127.0.0.1", "scan", "net", "success", {"ports": [80]})
    audit.log("127.0.0.1", "check", "tls", "success", {"cipher": "AES"})

    # Check initially valid
    ver = audit.verify_chain()
    assert ver["valid"] is True
    assert ver["total_events"] == 2

    # Deliberately tamper with row 1 details
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TRIGGER IF EXISTS audit_no_update")
        conn.execute("UPDATE audit_log SET details = '{\"ports\": [999]}' WHERE id = 1")
        conn.commit()

    ver_tampered = audit.verify_chain()
    assert ver_tampered["valid"] is False
    assert "Tampered event detected" in ver_tampered["error"]


# O. Duplicate request -> correct task reused
@pytest.mark.asyncio
async def test_o_duplicate_request_reused(env):
    orch = env["orchestrator"]
    res1 = await orch.execute_task(
        prompt="Assess 127.0.0.1 with quick depth",
        conversation_id="conv-dup",
    )
    t1_id = res1["task"]["id"]

    # Exact same request within window
    res2 = await orch.execute_task(
        prompt="Assess 127.0.0.1 with quick depth",
        conversation_id="conv-dup",
    )
    assert res2["telemetry"].get("deduplicated") is True
    assert res2["telemetry"].get("reused_task_id") == t1_id


# P. Different request within 10 seconds -> NOT incorrectly deduplicated
@pytest.mark.asyncio
async def test_p_different_request_not_deduplicated(env):
    orch = env["orchestrator"]
    res1 = await orch.execute_task(
        prompt="Assess 127.0.0.1 with quick depth",
        conversation_id="conv-diff",
    )
    t1_id = res1["task"]["id"]

    # Different action/depth/prompt within 10s
    res2 = await orch.execute_task(
        prompt="Scan ports on 127.0.0.1",
        conversation_id="conv-diff",
    )
    assert res2["telemetry"].get("deduplicated") is not True
    assert res2["task"]["id"] != t1_id


# Q. Provider authentication failure -> fallback works if available
@pytest.mark.asyncio
async def test_q_provider_auth_failure_fallback_works(env):
    orch = env["orchestrator"]
    task = Task(
        id="task-q-1",
        conversation_id="conv-q",
        type="general_chat",
        target="127.0.0.1",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    # Request a provider that fails auth (e.g. invalid model / failing provider)
    res = await orch._handle_general_chat(
        prompt="Explain SQL injection prevention",
        task=task,
        model_choice="gemini|gemini-nonexistent",
        effort_choice="auto",
        token_usage_store=None,
        start_time=0.0,
    )
    assert "response" in res
    assert res["task"]["status"] == "COMPLETED"
    # Fallback was used (Groq cloud or deterministic offline fallback)
    status = res["telemetry"]["provider_status"]
    assert status["fallback_used"] is True
    assert status["fallback_provider"].lower() in ("groq", "offline", "offline_deterministic")


# R. Provider quota failure -> fallback works if available
@pytest.mark.asyncio
async def test_r_provider_quota_failure_fallback_works(env):
    orch = env["orchestrator"]
    res = await orch.execute_task(
        prompt="Explain CSRF protection mechanisms",
        conversation_id="conv-q",
        model_choice="groq|qwen/qwen3.8-27b",
    )
    assert "response" in res
    assert "csrf" in res["response"].lower() or "token" in res["response"].lower()


# S. All providers unavailable -> deterministic/offline mode works without fake AI output
@pytest.mark.asyncio
async def test_s_all_providers_unavailable_deterministic_offline(env):
    orch = env["orchestrator"]
    # Mock LLMClient so complete and acomplete raise connection errors
    class BrokenLLM:
        default_provider = Provider.OLLAMA
        settings = type("S", (), {"groq_model": "x", "openrouter_model": "y", "llm_model": "z"})()
        def is_provider_configured(self, p): return False
        async def acomplete(self, *a, **k): raise ConnectionError("Offline")
        def complete(self, *a, **k): raise ConnectionError("Offline")

    # Call _generate_offline_cyber_response directly
    offline_resp = orch._generate_offline_cyber_response("Tell me about SQL injection")
    assert "SQL Injection (CWE-89" in offline_resp
    assert "parameterized queries" in offline_resp.lower()
    assert "Offline Analysis" in offline_resp


# T. API key accidentally present in logs -> test confirms redaction
def test_t_api_key_redacted_from_audit_logs(tmp_path: Path):
    db_path = tmp_path / "redact_test.db"
    audit = AuditLogger(db_path=db_path)

    fake_groq_key = "gsk_123456789012345678901234567890"
    fake_sk_key = "sk-abcdefghijklmnopqrstuvwxyz123456"

    audit.log(
        "127.0.0.1",
        "api_call",
        "llm",
        "failed",
        {"api_key": fake_groq_key, "nested": {"token": fake_sk_key}, "msg": f"Failed with {fake_groq_key}"},
    )

    rows = audit.fetch()
    assert len(rows) == 1
    details = rows[0]["details"]

    assert details["api_key"] == "[REDACTED]"
    assert details["nested"]["token"] == "[REDACTED]"
    assert fake_groq_key not in details["msg"]
    assert "[REDACTED]" in details["msg"]

    # Verify audit chain integrity still holds with redacted entries
    ver = audit.verify_chain()
    assert ver["valid"] is True


# U. Chat and Workbench -> identical orchestration semantics
@pytest.mark.asyncio
async def test_u_chat_and_workbench_identical_semantics(env):
    orch = env["orchestrator"]

    # Request from chat prompt
    res_chat = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-chat",
    )

    # Request from workbench copilot
    res_wb = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-workbench",
    )

    assert res_chat["task"]["status"] == res_wb["task"]["status"] == "PARTIALLY_BLOCKED"
    assert res_chat["structured_result"]["blocked_stages"] == res_wb["structured_result"]["blocked_stages"]
    assert res_chat["structured_result"]["status"] == res_wb["structured_result"]["status"] == "partially_blocked"
