"""Test suite verifying strict per-request target resolution, task-context isolation,
and prevention of cross-task context contamination (REDLOOP Phase 1).

10 Required Regression Scenarios:
1. New IP prompt uses newly supplied IP (overrides previous context IP).
2. New domain prompt does not reuse earlier email target.
3. General question executes with target=None/"" and target_type="none".
4. Email task rejects IP indicator with actionable clarification.
5. Missing target produces clarification request (never silently scans 127.0.0.1).
6. Specific investigation can be referenced explicitly by ID.
7. Unrelated task does not inherit previous investigation findings or evidence.
8. Concurrent tasks with different targets remain strictly isolated.
9. Stale global state.target is overridden by explicit prompt target.
10. Unauthorized network targets blocked by scope contract.
"""

from __future__ import annotations

import asyncio
import tempfile
from typing import Any
import pytest
import yaml

from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.orchestrator import AssessmentDepth, Task, TaskOrchestrator
from redloop.investigation import Investigation, get_investigation_store
from redloop.scope import ScopeManager, UnauthorizedTargetError, sign_scope

SECRET = "redloop-test-secret-isolation-key"


# Module-level fast test handlers (replaces slow external LLMs & actual raw socket commands)
async def _fast_mock_general_chat(self, prompt, task, **kwargs):
    task.status = "COMPLETED"
    task.response_text = "General cyber reasoning output"
    self.task_store.save(task)
    return {
        "response": task.response_text,
        "task": task.to_dict(),
        "assessment_id": None,
        "conversation_id": task.conversation_id,
        "telemetry": {"latency_ms": 1.0},
    }


def _fast_mock_tool_action(self, action, target, task, start_time, intent, prompt):
    task.status = "COMPLETED"
    task.target = target
    task.response_text = f"Executed {action} on {target}"
    self.task_store.save(task)
    return {
        "response": task.response_text,
        "task": task.to_dict(),
        "target": target,
        "assessment_id": None,
        "conversation_id": task.conversation_id,
        "telemetry": {"latency_ms": 1.0},
    }


TaskOrchestrator._handle_general_chat = _fast_mock_general_chat
TaskOrchestrator._handle_tool_action = _fast_mock_tool_action


@pytest.fixture
def temp_audit_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        return f.name


@pytest.fixture
def mock_scope_manager(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    raw = {
        "version": 1,
        "id": "isolation-test",
        "authorized_by": "Security Lead",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Local loopback",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["*"],
            },
            {
                "cidr": "192.168.1.0/24",
                "label": "Internal test lab",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["*"],
            },
            {
                "domain": "authorized.local",
                "label": "Authorized internal domain",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["*"],
            },
        ],
    }
    raw["signature"] = sign_scope(raw, SECRET)
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return ScopeManager(str(scope_yaml), secret=SECRET)


@pytest.fixture
def orchestrator(temp_audit_db, mock_scope_manager):
    return TaskOrchestrator(
        scope_manager=mock_scope_manager,
        audit_db=temp_audit_db,
    )


# ==============================================================================
# Scenario 1: New IP prompt uses newly supplied IP (not previous context IP)
# ==============================================================================
def test_scenario_1_new_ip_overrides_previous_context_ip(orchestrator):
    prompt = "Scan 192.168.1.99"
    context = {"target": "10.0.0.1", "current_ui_target": "10.0.0.1"}

    intent = orchestrator.parse_intent(prompt, context)
    assert intent["target"] == "192.168.1.99"
    assert intent["target_type"] == "ip"
    assert intent.get("resolution_source") == "prompt"


# ==============================================================================
# Scenario 2: New domain prompt does not reuse earlier email target
# ==============================================================================
def test_scenario_2_new_domain_does_not_reuse_earlier_email(orchestrator):
    prompt = "Investigate domain example.org"
    context = {"investigation_target": "admin@corp.com", "target": "admin@corp.com"}

    intent = orchestrator.parse_intent(prompt, context)
    assert intent["target"] == "example.org"
    assert intent["target_type"] == "domain"
    assert intent["action"] == "osint_domain"
    assert "admin@corp.com" not in intent["target"]


# ==============================================================================
# Scenario 3: General question without target executes with target=None/""
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_3_general_question_has_no_target(orchestrator):
    prompt = "What is SSRF and how does DNS rebinding bypass filters?"
    context = {"target": "127.0.0.1", "current_ui_target": "127.0.0.1"}

    intent = orchestrator.parse_intent(prompt, context)
    assert intent["action"] == "general_chat"
    assert intent["target"] == ""
    assert intent["target_type"] == "none"

    result = await orchestrator.execute_task(
        prompt=prompt,
        conversation_id="conv-general-test",
        context=context,
    )
    req_ctx = result.get("request_context", {})
    assert req_ctx.get("explicit_target") is None
    assert req_ctx.get("target_type") == "none"
    assert result.get("task", {}).get("target") == ""


# ==============================================================================
# Scenario 4: Email task rejecting IP indicator
# ==============================================================================
def test_scenario_4_email_task_rejects_ip_indicator(orchestrator):
    prompt = "Investigate email 192.168.1.1"
    intent = orchestrator.parse_intent(prompt)

    assert intent["action"] == "target_clarification_required"
    assert intent["intent"] == "TARGET_CLARIFICATION_REQUIRED"
    assert "Target type mismatch" in intent["clarification_message"]
    assert "Email intelligence requires a valid email" in intent["clarification_message"]


# ==============================================================================
# Scenario 5: Missing target produces clarification request (no silent 127.0.0.1)
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_5_missing_target_requests_clarification(orchestrator):
    prompt = "Run port scan"
    intent = orchestrator.parse_intent(prompt)

    assert intent["action"] == "target_clarification_required"
    assert intent["target"] == ""
    assert "Missing target" in intent["clarification_message"]

    result = await orchestrator.execute_task(
        prompt=prompt,
        conversation_id="conv-missing-target",
    )
    assert result.get("task", {}).get("status") == "CLARIFICATION_REQUIRED"
    assert "Target Clarification Required" in result.get("response", "")
    # Must NEVER have scanned 127.0.0.1!
    assert result.get("task", {}).get("target") == ""


# ==============================================================================
# Scenario 6: Explicit investigation referencing
# ==============================================================================
def test_scenario_6_explicit_investigation_referencing(orchestrator):
    inv_store = get_investigation_store()
    inv_a = Investigation(id="inv-alpha-test", title="Alpha Audit", target="192.168.1.10", objective="Internal assessment")
    inv_b = Investigation(id="inv-beta-test", title="Beta Audit", target="192.168.1.20", objective="Secondary assessment")
    inv_store.save(inv_a)
    inv_store.save(inv_b)

    prompt = f"Summarize previous investigation {inv_b.id}"
    intent = orchestrator.parse_intent(prompt)

    assert intent["action"] == "follow_up_investigation"
    assert intent["investigation_id"] == inv_b.id

    task = Task(id="task-test", conversation_id="conv-test", type="follow_up_investigation", target="")
    res = orchestrator._handle_follow_up_investigation(
        task=task,
        start_time=0.0,
        investigation_id=inv_b.id,
    )
    assert inv_b.id in res["response"]
    assert "Beta Audit" in res["response"]
    assert "Alpha Audit" not in res["response"]


# ==============================================================================
# Scenario 7: Unrelated task does not inherit previous investigation findings
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_7_unrelated_task_does_not_inherit_findings(orchestrator):
    inv_store = get_investigation_store()
    inv = Investigation(id="inv-classified-test", title="Critical Pentest", target="10.99.99.99", objective="Classified Audit")
    inv.finding_ids = ["find-classified-01", "find-classified-02"]
    inv_store.save(inv)

    # General question about cryptography
    prompt = "Explain the mathematical difference between RSA and Elliptic Curve Cryptography"
    intent = orchestrator.parse_intent(prompt)
    assert intent["action"] == "general_chat"
    assert intent["target"] == ""

    result = await orchestrator.execute_task(
        prompt=prompt,
        conversation_id="conv-crypto-chat",
    )
    # Target and findings from the active investigation must NOT leak into this general chat
    assert result.get("task", {}).get("target") == ""
    assert "find-classified-01" not in result.get("response", "")
    req_ctx = result.get("request_context", {})
    assert req_ctx.get("explicit_target") is None
    assert req_ctx.get("task_type") == "general_chat"


# ==============================================================================
# Scenario 8: Concurrent tasks with different targets remain isolated
# ==============================================================================
@pytest.mark.asyncio
async def test_scenario_8_concurrent_tasks_remain_isolated(orchestrator):
    prompt_1 = "Scan 192.168.1.101"
    prompt_2 = "Scan 192.168.1.202"

    async def run_task(p: str, conv: str):
        return await orchestrator.execute_task(prompt=p, conversation_id=conv)

    task1_coro = run_task(prompt_1, "conv-1")
    task2_coro = run_task(prompt_2, "conv-2")

    res1, res2 = await asyncio.gather(task1_coro, task2_coro)

    target1 = res1.get("request_context", {}).get("explicit_target")
    target2 = res2.get("request_context", {}).get("explicit_target")

    assert target1 == "192.168.1.101"
    assert target2 == "192.168.1.202"
    assert target1 != target2
    assert res1.get("task", {}).get("target") == "192.168.1.101"
    assert res2.get("task", {}).get("target") == "192.168.1.202"


# ==============================================================================
# Scenario 9: Stale global state.target overridden by request target
# ==============================================================================
def test_scenario_9_stale_global_target_overridden_by_request_target(orchestrator):
    stale_context = {
        "target": "127.0.0.1",
        "current_ui_target": "127.0.0.1",
        "ambient_target": "127.0.0.1",
    }
    prompt = "Scan 192.168.1.55"

    intent = orchestrator.parse_intent(prompt, context=stale_context)
    assert intent["target"] == "192.168.1.55"
    assert intent["target"] != "127.0.0.1"
    assert intent["target_type"] == "ip"
    assert intent.get("resolution_source") == "prompt"


# ==============================================================================
# Scenario 10: Unauthorized network targets blocked by scope contract
# ==============================================================================
def test_scenario_10_unauthorized_network_targets_blocked(orchestrator):
    # 8.8.8.8 is NOT in mock_scope_manager (which only allows 127.0.0.1, 192.168.1.0/24, authorized.local)
    unauthorized_ip = "8.8.8.8"
    with pytest.raises(UnauthorizedTargetError):
        orchestrator.scope_manager.check(unauthorized_ip, "port_scan")

    prompt = f"Run full assessment on {unauthorized_ip}"
    intent = orchestrator.parse_intent(prompt)
    assert intent["target"] == unauthorized_ip
    assert intent["action"] == "run_assessment"

    task = Task(
        id="task-unauth-test",
        conversation_id="conv-scope-test",
        type="run_assessment",
        target=unauthorized_ip,
    )
    orchestrator.task_store.save(task)

    result = orchestrator._handle_run_assessment(
        target=unauthorized_ip,
        depth=AssessmentDepth.STANDARD,
        task=task,
        start_time=0.0,
    )

    # Verification: Assessment must be BLOCKED
    assert task.status in ("BLOCKED", "PARTIALLY_BLOCKED")
    assert "Target Outside Active Signed Scope" in result["response"]
    assert "0 network packets transmitted" in result["response"]
