"""Regression test suite for REDLOOP Policy-Enforced Autonomous Execution.

Proves:
1. An authorized hostname executes all applicable permitted stages.
2. An unauthorized hostname produces a structured blocked-stage result without authorization scaffolding.
3. A blocked network stage does not prevent unrelated permitted local stages.
4. The final Copilot response adheres to strict blocked-target information isolation.
5. Existing local historical evidence from prior authorized operations can be reviewed without a network scan.
6. No findings are fabricated for blocked stages; reports NO LOCAL EVIDENCE AVAILABLE when no prior evidence exists.
7. Direct REST requests cannot bypass scope enforcement.
8. Fallback probes cannot bypass scope enforcement.
9. Chat and Workbench use the same orchestration behavior.
10. An unauthorized task NEVER generates scope.yaml content, signing commands, or blueprints.
11. Audit records preserve blocked decisions with cryptographically verifiable hash chain.
12. Deduplication prevents duplicate tasks during retries/fallbacks.
"""

from __future__ import annotations

import asyncio
from datetime import date, timedelta
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
    Finding,
    Severity,
    StageStatus,
)
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.tls_engine import TLSEngine
from redloop.assessment.web_engine import WebEngine
from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def copilot_env(tmp_path: Path):
    """Setup isolated test environment with signed scope, audit DB, and assessment store."""
    today = date.today()
    scope_data = {
        "version": 1,
        "id": "copilot-policy-enforced-test",
        "authorized_by": "copilot-tests",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback-authorized",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["scan", "recon", "check", "assess", "web_check", "tls_check", "dns_check"],
                "ports": [80, 443, 8080, 8765],
            },
        ],
    }
    secret = "copilot-test-secret-key-32-bytes-long"
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")

    scope_mgr = ScopeManager(scope_file, secret)
    audit_db = tmp_path / "audit.sqlite"
    audit = AuditLogger(audit_db)
    task_db = tmp_path / "tasks.sqlite"
    asmt_db = tmp_path / "assessments.sqlite"

    orch = TaskOrchestrator(
        scope_manager=scope_mgr,
        audit_db=audit_db,
        task_db=task_db,
        assessment_db=asmt_db,
    )

    return {
        "orchestrator": orch,
        "scope_manager": scope_mgr,
        "audit": audit,
        "audit_db": audit_db,
        "asmt_store": AssessmentStore(asmt_db),
        "scope_guard": AssessmentScopeGuard(scope_mgr, audit),
        "scope_file": scope_file,
    }


# ---------------------------------------------------------------------------
# Test 1: An authorized hostname executes all applicable permitted stages
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_authorized_hostname_executes_permitted_stages(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess 127.0.0.1",
        conversation_id="conv-auth-1",
    )

    assert result["task"]["status"] in ("COMPLETED", "PARTIALLY_BLOCKED")
    assert result["structured_result"]["status"] in ("completed", "partially_blocked")
    assert result["assessment_id"] is not None

    executed = result["structured_result"]["executed_stages"]
    assert "dns_discovery" in executed or "network_discovery" in executed
    assert "correlation_and_risk" in executed
    assert "ai_analysis" in executed


# ---------------------------------------------------------------------------
# Test 2: An unauthorized hostname produces a structured blocked-stage result
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_2_unauthorized_hostname_produces_structured_result(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-unauth-2",
    )

    assert "Operation Blocked by REDLOOP Scope Policy" not in result["response"]
    assert result["task"]["status"] == "PARTIALLY_BLOCKED"

    struct = result["structured_result"]
    assert struct["status"] == "partially_blocked"
    assert struct["target"] == "rathinamtechpark.com"
    assert struct["blocked_capability"] == "network_operations"
    assert "inspect_existing_local_evidence" in struct["available_next_actions"]
    assert "review_scope_configuration" in struct["available_next_actions"]
    # Scope scaffolding must NOT be present
    assert "scope_configuration_needed" not in struct
    assert "proposed_plan" not in struct

    # Blocked network stages recorded
    blocked = struct["blocked_stages"]
    assert "scope_validation" in blocked
    assert "dns_discovery" in blocked
    assert "network_discovery" in blocked


# ---------------------------------------------------------------------------
# Test 3: A blocked network stage does not prevent unrelated permitted stages
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_blocked_network_stage_does_not_abort_permitted_stages(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-progression-3",
    )

    struct = result["structured_result"]
    executed = struct["executed_stages"]

    # Local historical review ran to completion
    assert "local_evidence_review" in executed
    # When no prior evidence exists, correlation and AI are safely skipped to avoid speculative fabrication
    assert "correlation_and_risk" in struct["skipped_stages"]
    assert "ai_analysis" in struct["skipped_stages"]


# ---------------------------------------------------------------------------
# Test 4: The final Copilot response adheres to strict blocked isolation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_copilot_response_summarizes_actual_execution(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-summary-4",
    )

    response_text = result["response"]
    assert "rathinamtechpark.com" in response_text
    assert "Execution Pipeline" in response_text or "Pipeline Execution" in response_text
    assert "Local Evidence Review" in response_text
    assert "Scope Validation" in response_text

    # MUST NOT contain blueprint, scope.yaml snippet, or signing commands
    assert "Required Scope Authorization Blueprint" not in response_text
    assert "python -m redloop.cli scope sign" not in response_text
    assert "NO LOCAL EVIDENCE AVAILABLE." in response_text


# ---------------------------------------------------------------------------
# Test 5: Existing local evidence can be reviewed without a network scan
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_existing_local_evidence_reviewed_without_network_scan(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    asmt_store: AssessmentStore = copilot_env["asmt_store"]

    # Pre-populate historical evidence and finding for an out-of-scope target
    target = "cached-target.com"
    cached_finding = Finding(
        id="RL-FIND-9999",
        title="Prior Cached Vulnerability Test",
        category="recon",
        severity=Severity.HIGH,
        asset=target,
        target=target,
        description="Historical finding stored from earlier assessment.",
    )
    cached_evidence = Evidence(
        id="RL-EVI-8888",
        target=target,
        response_excerpt="HTTP 200 OK Historical Cache Excerpt",
    )
    pre_state = AssessmentState(
        id="asmt-cached-prior",
        target=target,
        status="COMPLETED",
        findings=[cached_finding],
        evidence=[cached_evidence],
    )
    asmt_store.save(pre_state)

    result = await orch.execute_task(
        prompt=f"Assess {target}",
        conversation_id="conv-cache-5",
    )

    # Must review local store and report 1 prior finding without network scanning
    assert cached_finding.id in result["task"]["finding_ids"]
    assert "Prior Cached Vulnerability Test" in result["response"]
    assert "Found `1` historical finding(s)" in result["response"]


# ---------------------------------------------------------------------------
# Test 6: No findings are fabricated for blocked stages
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_6_no_findings_fabricated_for_blocked_stages(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-zero-fab-6",
    )

    # Zero findings and evidence when target has no prior data
    assert len(result["task"]["finding_ids"]) == 0
    assert len(result["task"]["evidence_ids"]) == 0
    assert "NO LOCAL EVIDENCE AVAILABLE." in result["response"]
    assert "`0` TCP/UDP packets or DNS queries transmitted" in result["response"]


# ---------------------------------------------------------------------------
# Test 7: Direct REST requests cannot bypass scope enforcement
# ---------------------------------------------------------------------------
def test_7_direct_rest_requests_cannot_bypass_scope(copilot_env):
    app = create_app(
        str(copilot_env["audit_db"]),
        copilot_env["scope_manager"],
    )

    async def run_req():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            tls_resp = await client.post(
                "/api/workbench/red/tls-check",
                json={"target": "127.0.0.1", "port": 9999},
                headers={"Origin": "http://testserver"},
            )
            web_resp = await client.post(
                "/api/workbench/red/web-check",
                json={"url": "http://rathinamtechpark.com"},
                headers={"Origin": "http://testserver"},
            )
            return tls_resp, web_resp

    tls_resp, web_resp = asyncio.run(run_req())
    assert tls_resp.status_code == 403
    assert web_resp.status_code in (400, 403)


# ---------------------------------------------------------------------------
# Test 8: Fallback probes cannot bypass scope enforcement
# ---------------------------------------------------------------------------
def test_8_fallback_probes_cannot_bypass_scope(copilot_env):
    guard: AssessmentScopeGuard = copilot_env["scope_guard"]
    audit: AuditLogger = copilot_env["audit"]

    # 1. Guard check raises ScopeBlockedError
    with pytest.raises(ScopeBlockedError):
        guard.verify_operation("rathinamtechpark.com", "scan")

    # 2. DNS Engine returns BLOCKED
    dns_res = DNSEngine(guard, audit).assess_target("rathinamtechpark.com")
    assert dns_res.status == StageStatus.BLOCKED
    assert len(dns_res.findings) == 0

    # 3. TLS Engine returns BLOCKED
    tls_res = TLSEngine(guard, audit).assess_target("rathinamtechpark.com")
    assert tls_res.status == StageStatus.BLOCKED
    assert len(tls_res.findings) == 0

    # 4. Web Engine returns BLOCKED
    web_res = WebEngine(guard, audit).assess_url("http://rathinamtechpark.com")
    assert web_res.status == StageStatus.BLOCKED
    assert len(web_res.findings) == 0

    # 5. API Engine returns BLOCKED
    api_res = APIEngine(guard, audit).assess_api("http://rathinamtechpark.com")
    assert api_res.status == StageStatus.BLOCKED
    assert len(api_res.findings) == 0


# ---------------------------------------------------------------------------
# Test 9: Chat and Workbench use the same orchestration behavior
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_chat_and_workbench_use_same_orchestration(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]

    # Request via Chat context
    chat_res = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="chat-conv-user-1",
        context={"channel": "chat"},
    )

    # Request via Workbench context
    wb_res = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="workbench-copilot",
        context={"channel": "workbench"},
    )

    assert chat_res["task"]["status"] == "PARTIALLY_BLOCKED"
    assert wb_res["task"]["status"] == "PARTIALLY_BLOCKED"
    assert chat_res["structured_result"]["target"] == wb_res["structured_result"]["target"]
    assert chat_res["structured_result"]["blocked_capability"] == wb_res["structured_result"]["blocked_capability"]


# ---------------------------------------------------------------------------
# Test 10: Unauthorized target NEVER generates scope.yaml content or signing commands
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_10_unauthorized_target_never_generates_blueprints(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    result = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-plan-10",
    )

    response = result["response"]
    # Absolutely NO prepared blueprint or generated scope.yaml
    assert "Required Scope Authorization Blueprint" not in response
    assert "scope.yaml" not in response
    assert "python -m redloop.cli scope sign" not in response
    assert "targets:" not in response
    assert 'value: "rathinamtechpark.com"' not in response
    # States outside active signed scope and NO LOCAL EVIDENCE AVAILABLE
    assert "outside the active signed scope" in response or "outside active scope" in response
    assert "NO LOCAL EVIDENCE AVAILABLE." in response


# ---------------------------------------------------------------------------
# Test 11: Audit records preserve blocked decisions
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_11_audit_records_preserve_blocked_decisions(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]
    audit: AuditLogger = copilot_env["audit"]

    await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-audit-11",
    )

    entries = audit.fetch(target="rathinamtechpark.com")
    assert len(entries) > 0

    blocked_entries = [e for e in entries if e["status"] == "blocked"]
    assert len(blocked_entries) >= 1
    assert any(e["module"] == "scope_guard" for e in blocked_entries)

    # Verify cryptographic SHA-256 tamper-evident integrity of audit ledger
    chain_info = audit.verify_chain()
    assert chain_info["valid"] is True


# ---------------------------------------------------------------------------
# Test 12: Deduplication prevents duplicate task execution
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_12_deduplication_prevents_duplicate_tasks(copilot_env):
    orch: TaskOrchestrator = copilot_env["orchestrator"]

    # First execution
    res1 = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-dedup-12",
    )
    task1_id = res1["task"]["id"]

    # Fast retry within 10-second deduplication window
    res2 = await orch.execute_task(
        prompt="Assess rathinamtechpark.com",
        conversation_id="conv-dedup-12",
    )

    assert res2["telemetry"].get("deduplicated") is True
    assert res2["telemetry"].get("reused_task_id") == task1_id
    assert res2["task"]["id"] == task1_id
