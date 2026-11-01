"""Regression tests for intent-parsing subdomain collision (Part 1, Item 7).

Verifies that explicit assessment or scanning verbs against domain-looking targets
(.io, .internal, etc.) take strict precedence and are NEVER misclassified as
passive OSINT_DOMAIN queries.
"""

from __future__ import annotations

import pytest
from redloop.assessment.orchestrator import TaskOrchestrator


@pytest.fixture
def orchestrator() -> TaskOrchestrator:
    return TaskOrchestrator()


ADVERSARIAL_SCAN_ASSESS_CASES = [
    ("assess api.internal.io", "VULNERABILITY_ASSESSMENT", "run_assessment", "api.internal.io"),
    ("scan backend.io for open ports", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "backend.io"),
    ("run assessment on target.io", "VULNERABILITY_ASSESSMENT", "run_assessment", "target.io"),
    ("scan https://sub.domain.io with nmap", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "sub.domain.io"),
    ("assess portal.cloud.io full scan", "VULNERABILITY_ASSESSMENT", "run_assessment", "portal.cloud.io"),
    ("probe service.mesh.io on port 443", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "service.mesh.io"),
    ("evaluate security for internal.app.io", "VULNERABILITY_ASSESSMENT", "run_assessment", "internal.app.io"),
    ("run nmap against db.cluster.io", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "db.cluster.io"),
    ("scan authorized host web.staging.io", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "web.staging.io"),
    ("assess auth.gateway.io", "VULNERABILITY_ASSESSMENT", "run_assessment", "auth.gateway.io"),
    ("please assess api.internal.io", "VULNERABILITY_ASSESSMENT", "run_assessment", "api.internal.io"),
    ("can you scan edge.prod.io for open ports?", "AUTHORIZED_RECONNAISSANCE", "tool_ports", "edge.prod.io"),
    ("nikto scan http://vuln.lab.io", "AUTHORIZED_RECONNAISSANCE", "tool_nikto", "vuln.lab.io"),
    ("gobuster scan http://api.cloud.io", "AUTHORIZED_RECONNAISSANCE", "tool_gobuster", "api.cloud.io"),
]


@pytest.mark.parametrize("prompt,expected_intent,expected_action,expected_target", ADVERSARIAL_SCAN_ASSESS_CASES)
def test_adversarial_subdomain_collision(
    orchestrator: TaskOrchestrator,
    prompt: str,
    expected_intent: str,
    expected_action: str,
    expected_target: str,
) -> None:
    intent = orchestrator.parse_intent(prompt)
    assert intent["intent"] != "OSINT_DOMAIN", f"Prompt '{prompt}' misclassified as passive OSINT_DOMAIN!"
    assert intent["intent"] != "OSINT_IP", f"Prompt '{prompt}' misclassified as passive OSINT_IP!"
    assert intent["intent"] == expected_intent, f"Prompt '{prompt}' got {intent['intent']}, expected {expected_intent}"
    assert intent["action"] == expected_action, f"Prompt '{prompt}' got action {intent['action']}, expected {expected_action}"
    if expected_target:
        assert expected_target in intent["target"], f"Target {intent['target']} did not contain {expected_target}"


LEGITIMATE_OSINT_CASES = [
    ("investigate 8.8.8.8", "OSINT_IP", "osint_ip"),
    ("investigate example.com", "OSINT_DOMAIN", "osint_domain"),
    ("whois example.com", "OSINT_DOMAIN", "osint_domain"),
    ("subdomains for target.io", "OSINT_DOMAIN", "osint_domain"),
    ("shodan 8.8.8.8", "OSINT_IP", "osint_ip"),
    ("investigate email test@example.com", "OSINT_EMAIL", "osint_email"),
    ("investigate phone +14155552671", "OSINT_PHONE", "osint_phone"),
    ("investigate username admin", "OSINT_USERNAME", "osint_username"),
]


@pytest.mark.parametrize("prompt,expected_intent,expected_action", LEGITIMATE_OSINT_CASES)
def test_legitimate_osint_queries_preserved(
    orchestrator: TaskOrchestrator,
    prompt: str,
    expected_intent: str,
    expected_action: str,
) -> None:
    intent = orchestrator.parse_intent(prompt)
    assert intent["intent"] == expected_intent, f"Legitimate OSINT '{prompt}' got {intent['intent']}, expected {expected_intent}"
    assert intent["action"] == expected_action
