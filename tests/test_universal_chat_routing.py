"""Comprehensive Test Suite for Universal Chat Intelligence & Intent Routing Pipeline.

Verifies:
1. "Explain what DNS is." -> Answers normally without executing security tools.
2. "Write a Java program for sorting an array." -> Generates code cleanly without security tool activation.
3. "Investigate this public IP." -> Validates indicator and executes IP intelligence pipeline.
4. "Scan this authorized lab target." -> Validates scope contract and executes tool safely.
5. "Here is my Nmap output; what next?" -> Ingests and parses actual terminal output and recommends next command.
6. "Solve this CTF and identify the real flag." -> Distinguishes decoy flags and verifies real candidate flag.
7. "Extract metadata from this image." -> Executes metadata analysis pipeline.
8. "Summarize the findings from our previous investigation." -> Faithfully retrieves persisted investigation.
9. "What does this scan result mean?" -> Explains scan result before recommending further execution.
10. Fail-closed scope gate on unauthorized targets.
11. All 17 major intents route deterministically.
"""

import asyncio
import pytest

from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.audit import AuditLogger
from redloop.investigation import Investigation, get_investigation_store
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def test_env(tmp_path):
    from datetime import date, timedelta
    import yaml
    
    audit_db = str(tmp_path / "audit.sqlite")
    scope_file = tmp_path / "scope.yaml"
    secret = "test-secret-key-redloop-32bytes!!"
    today = date.today()
    
    scope_data = {
        "version": 1,
        "id": "test-scope",
        "authorized_by": "test",
        "signed_at": "2026-10-26T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["scan", "check", "assess", "probe", "recon", "tool_ports", "tool_tls", "tool_web"],
                "ports": [80, 443, 8080],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    scope_mgr = ScopeManager(scope_file, secret)
    orch = TaskOrchestrator(scope_manager=scope_mgr, audit_db=audit_db)
    return orch, tmp_path


@pytest.mark.asyncio
async def test_01_explain_dns_without_tools(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Explain what DNS is.")
    assert intent["intent"] == "GENERAL_CHAT"
    assert intent["action"] == "general_chat"

    res = await orch.execute_task(
        prompt="Explain what DNS is.",
        conversation_id="conv-test-01",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "DNS" in res["response"] or "Domain Name System" in res["response"]
    # Ensure no assessment ID or tool execution occurred
    assert res.get("assessment_id") is None
    assert "tool" not in res["task"]["type"]


@pytest.mark.asyncio
async def test_02_write_java_program_sorting_array(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Write a Java program for sorting an array.")
    assert intent["intent"] == "CODING_AND_RESEARCH"
    assert intent["action"] == "coding_and_research"

    res = await orch.execute_task(
        prompt="Write a Java program for sorting an array.",
        conversation_id="conv-test-02",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "```java" in res["response"]
    assert "Arrays.sort" in res["response"] or "quickSort" in res["response"]
    assert "tool" not in res["task"]["type"]


@pytest.mark.asyncio
async def test_03_investigate_public_ip(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Investigate this public IP 8.8.8.8")
    assert intent["intent"] == "OSINT_IP"
    assert intent["action"] == "osint_ip"
    assert intent["target"] == "8.8.8.8"

    res = await orch.execute_task(
        prompt="Investigate this public IP 8.8.8.8",
        conversation_id="conv-test-03",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "OSINT Intelligence" in res["response"]
    assert "8.8.8.8" in res["response"]
    assert "Cryptographic Hash (SHA-256)" in res["response"]
    assert "osint_result" in res


@pytest.mark.asyncio
async def test_04_scan_authorized_lab_target(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Scan this authorized lab target 127.0.0.1")
    assert intent["intent"] == "AUTHORIZED_RECONNAISSANCE"
    assert intent["action"] == "tool_ports"
    assert intent["target"] == "127.0.0.1"

    res = await orch.execute_task(
        prompt="Scan this authorized lab target 127.0.0.1",
        conversation_id="conv-test-04",
    )
    assert res["task"]["status"] in ("COMPLETED", "SUCCESS")
    assert "127.0.0.1" in res["response"]
    assert res["task"]["scope_authorized"] is True


@pytest.mark.asyncio
async def test_05_unauthorized_target_fails_closed(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Scan this authorized lab target 192.168.1.55")
    assert intent["intent"] == "AUTHORIZED_RECONNAISSANCE"
    assert intent["target"] == "192.168.1.55"

    res = await orch.execute_task(
        prompt="Scan this authorized lab target 192.168.1.55",
        conversation_id="conv-test-05",
    )
    assert res["task"]["status"] in ("PARTIALLY_BLOCKED", "BLOCKED")
    assert res["task"]["scope_authorized"] is False
    assert "signed scope contract" in res["response"].lower()


@pytest.mark.asyncio
async def test_06_here_is_my_nmap_output_what_next(test_env):
    orch, _ = test_env
    nmap_raw = (
        "Starting Nmap 7.80 ( https://nmap.org ) at 2026-10-26 12:00 UTC\n"
        "Nmap scan report for 127.0.0.1\n"
        "PORT     STATE SERVICE VERSION\n"
        "80/tcp   open  http    Apache httpd 2.4.41\n"
        "8080/tcp open  http    Apache Tomcat 9.0.31\n"
    )
    intent = orch.parse_intent(f"Here is my Nmap output; what next?\n{nmap_raw}")
    assert intent["intent"] == "TERMINAL_OUTPUT_ANALYSIS"
    assert intent["action"] == "terminal_analysis"

    res = await orch.execute_task(
        prompt=f"Here is my Nmap output; what next?\n{nmap_raw}",
        conversation_id="conv-test-06",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "Terminal & Scan Output Ingestion" in res["response"]
    assert "Port 80/tcp" in res["response"]
    assert "Recommended Next Step" in res["response"]


@pytest.mark.asyncio
async def test_07_what_does_this_scan_result_mean(test_env):
    orch, _ = test_env
    prompt = "What does this scan result mean? PORT 443/tcp open https nginx/1.18.0"
    intent = orch.parse_intent(prompt)
    assert intent["intent"] == "TERMINAL_OUTPUT_ANALYSIS"
    assert intent["action"] == "terminal_analysis"

    res = await orch.execute_task(prompt=prompt, conversation_id="conv-test-07")
    assert res["task"]["status"] == "COMPLETED"
    assert "Technical Assessment of Results" in res["response"]


@pytest.mark.asyncio
async def test_08_solve_ctf_and_identify_real_flag_distinguishing_decoys(test_env):
    orch, _ = test_env
    ctf_prompt = (
        "Solve this CTF and identify the real flag.\n"
        "We analyzed the memory dump and found decoy token: flag{decoy_rabbit_hole_dont_submit_this}\n"
        "The real encoded challenge string was: ZmxhZ3tyZWFsX2NoYWxsZW5nZV9mbGFnXzEzMzd9\n"
    )
    intent = orch.parse_intent(ctf_prompt)
    assert intent["intent"] == "CTF_AND_CHALLENGE_ANALYSIS"
    assert intent["action"] == "ctf_analysis"

    res = await orch.execute_task(prompt=ctf_prompt, conversation_id="conv-test-08")
    assert res["task"]["status"] == "COMPLETED"
    assert "Decoy Flags Detected" in res["response"]
    assert "flag{decoy_rabbit_hole_dont_submit_this}" in res["response"]
    assert "flag{real_challenge_flag_1337}" in res["response"]


@pytest.mark.asyncio
async def test_09_extract_metadata_from_image(test_env):
    orch, _ = test_env
    intent = orch.parse_intent("Extract metadata from this image payload.")
    assert intent["intent"] == "FILE_METADATA_ANALYSIS"
    assert intent["action"] == "file_metadata_analysis"

    res = await orch.execute_task(
        prompt="Extract metadata from this image payload.",
        conversation_id="conv-test-09",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "OSINT Intelligence" in res["response"]
    assert "Cryptographic Hash (SHA-256)" in res["response"]


@pytest.mark.asyncio
async def test_10_summarize_findings_from_previous_investigation(test_env):
    orch, _ = test_env
    inv_store = get_investigation_store()
    test_inv = Investigation(
        id="inv-prev-test",
        title="Active Penetration Test Assessment",
        target="127.0.0.1",
        scope_status="AUTHORIZED",
        objective="Assess web vulnerabilities and open services",
    )
    test_inv.add_event("finding", "Observed Unauthenticated Tomcat Manager", "Severity HIGH")
    inv_store.save(test_inv)

    intent = orch.parse_intent("Summarize the findings from our previous investigation.")
    assert intent["intent"] == "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"
    assert intent["action"] == "follow_up_investigation"

    res = await orch.execute_task(
        prompt="Summarize the findings from our previous investigation.",
        conversation_id="conv-test-10",
    )
    assert res["task"]["status"] == "COMPLETED"
    assert "Active Investigation Summary" in res["response"]
    assert "127.0.0.1" in res["response"]
    assert "investigation" in res


@pytest.mark.asyncio
async def test_11_all_17_intents_classification(test_env):
    orch, _ = test_env
    intent_tests = [
        ("Explain what DNS is.", "GENERAL_CHAT"),
        ("Write a Java program for sorting an array.", "CODING_AND_RESEARCH"),
        ("Solve this CTF and identify the real flag.", "CTF_AND_CHALLENGE_ANALYSIS"),
        ("Analyze this Windows event log EventID 4625 brute force attempt", "FORENSICS_AND_LOG_ANALYSIS"),
        ("Here is my Nmap output; what next? PORT 80/tcp open http", "TERMINAL_OUTPUT_ANALYSIS"),
        ("How to use nmap on Kali Linux?", "KALI_COMMAND_ASSISTANCE"),
        ("Scan this authorized lab target 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
        ("Run comprehensive security assessment against 127.0.0.1", "VULNERABILITY_ASSESSMENT"),
        ("Investigate this public IP 1.1.1.1", "OSINT_IP"),
        ("Investigate domain redloop.local", "OSINT_DOMAIN"),
        ("Investigate email admin@redloop.local", "OSINT_EMAIL"),
        ("Investigate username sec_researcher", "OSINT_USERNAME"),
        ("Investigate phone +14155552671", "OSINT_PHONE"),
        ("Extract metadata from this image", "FILE_METADATA_ANALYSIS"),
        ("Show investigation graph", "GRAPH_AND_INVESTIGATION"),
        ("Generate technical report", "REPORT_GENERATION"),
        ("Summarize the findings from our previous investigation.", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"),
    ]

    for prompt, expected_intent in intent_tests:
        parsed = orch.parse_intent(prompt)
        assert parsed["intent"] == expected_intent, f"Prompt '{prompt}' classified as '{parsed['intent']}', expected '{expected_intent}'"
