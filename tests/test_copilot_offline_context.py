import pytest
import yaml
from redloop.assessment.orchestrator import TaskOrchestrator, TaskStore
from redloop.scope import ScopeManager, sign_scope

SECRET = "unit-test-secret"


@pytest.fixture
def orchestrator(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    raw = {
        "version": 1,
        "id": "unit-test",
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
            }
        ],
    }
    raw["signature"] = sign_scope(raw, SECRET)
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    sm = ScopeManager(str(scope_yaml), secret=SECRET)
    store = TaskStore()
    return TaskOrchestrator(scope_manager=sm, task_store=store)


def test_definitions_intent_classification(orchestrator):
    prompt = "What are definitions of vulnerability, exploit, and threat?"
    intent = orchestrator.parse_intent(prompt)
    assert intent.get("action") == "general_chat"
    # Must NOT classify as exploit simulation
    assert intent.get("action") != "exploit_simulation"


def test_definitions_offline_response_content(orchestrator):
    """General definitions query must return comprehensive definitions, not TCP port test script."""
    prompt = "What are definitions of vulnerability, exploit, and threat?"
    response = orchestrator._generate_offline_cyber_response(prompt)
    # Check for formal definitions
    assert "Vulnerability (The Flaw / Weakness)" in response
    assert "Exploit (The Weapon / Mechanism)" in response
    assert "Threat (The Adversary / Hazard)" in response
    # Check for risk equation
    assert "Risk" in response
    # Check for real web app walkthrough (SQLi / CWE-89)
    assert "SQL Injection" in response or "CWE-89" in response
    # Check for SOC walkthrough
    assert "Detection" in response
    assert "Investigation" in response
    assert "Remediation" in response
    # Crucial negative assertion: NO TCP port socket script
    assert "socket.socket" not in response
    assert "test_port" not in response


def test_multi_module_intelligence_intent_not_routed_to_email(orchestrator):
    prompt = "Summarize current IP, domain, and email intelligence records"
    intent = orchestrator.parse_intent(prompt)
    # Must NOT route to osint_email with target 127.0.0.1
    assert intent.get("action") != "osint_email"


def test_multi_module_intelligence_offline_response(orchestrator):
    prompt = "Summarize current IP, domain, and email intelligence"
    response = orchestrator._generate_offline_cyber_response(prompt)
    assert "Multi-Module Intelligence Synthesis" in response
    assert "IP Intelligence" in response
    assert "Domain Intelligence" in response
    assert "Email Footprint Intelligence" in response
    assert "Confirmed Observations" in response
    assert "Checks Not Performed" in response
    assert "Providers Not Configured" in response
    # IP must not be treated as an email
    assert "NEVER be evaluated or misclassified as an email" in response
    assert "invalid email address" not in response


def test_email_safety_evaluation_offline_response(orchestrator):
    prompt = "Is user@example.com safe when HIBP was not checked?"
    response = orchestrator._generate_offline_cyber_response(prompt)
    assert "Evidence-Based Security Evaluation" in response
    assert "Absence of Evidence is NOT Evidence of Absence" in response
    assert "NOT_CHECKED" in response or "PROVIDER_NOT_CONFIGURED" in response
    assert "zero breaches" in response.lower()  # Warning against zero breach assumption
    assert "socket.socket" not in response


@pytest.mark.asyncio
async def test_definitions_end_to_end_offline_execution(orchestrator, monkeypatch):
    async def mock_offline(*args, **kwargs):
        user_p = kwargs.get("user_prompt") or (args[1] if len(args) > 1 else "")
        offline_resp = orchestrator._generate_offline_cyber_response(user_p)
        return {"text": offline_resp, "content": offline_resp, "model": "offline-fallback"}, {"fallback_used": True}
    monkeypatch.setattr(orchestrator, "_execute_llm_with_fallback", mock_offline)

    res = await orchestrator.execute_task(
        prompt="What are definitions of vulnerability, exploit, and threat?",
        conversation_id="conv-offline-test",
    )
    result_text = res.get("response") or res.get("result", "")
    assert "Vulnerability" in result_text
    assert "Exploit" in result_text
    assert "Threat" in result_text
    assert "socket.socket" not in result_text
