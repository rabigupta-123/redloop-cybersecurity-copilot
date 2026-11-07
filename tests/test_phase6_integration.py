"""Phase 6 Automated Verification Suite: Full Platform Threat Hunting, ATT&CK & Detection Engineering Integration.

Contains 25 comprehensive end-to-end integration scenarios verifying:
1.  API: GET /api/hunting/attack/tactics returns all 14 tactics.
2.  API: GET /api/hunting/attack/techniques returns catalog techniques.
3.  API: GET /api/hunting/attack/techniques?tactic_id=TA0002 filters by tactic.
4.  API: POST /api/hunting/attack/map maps security events to ATT&CK.
5.  API: POST /api/hunting/attack/map maps SOC alerts to ATT&CK.
6.  API: GET /api/hunting/attack/matrix returns JSON matrix heatmap.
7.  API: GET /api/hunting/attack/matrix?format=markdown returns Markdown table report.
8.  API: GET /api/hunting/sigma/matrix returns formal Sigma support matrix.
9.  API: POST /api/hunting/sigma/validate validates well-formed Sigma rule.
10. API: POST /api/hunting/sigma/validate rejects malformed YAML syntax.
11. API: POST /api/hunting/sigma/validate rejects missing required fields and conditions.
12. API: POST /api/hunting/sigma/validate blocks ReDoS regex patterns.
13. API: POST /api/hunting/sigma/test evaluates rule against payload-supplied events.
14. API: POST /api/hunting/sigma/test evaluates rule against live ingested events.
15. API: POST /api/hunting/query/plan returns explainable query plan and safety check.
16. API: POST /api/hunting/query/plan computes execution cost estimation accurately.
17. API: POST /api/hunting/query/plan clamps excessive limits to max safe ceiling (1000).
18. API: POST /api/hunting/query/execute executes hunt and confirms hypothesis.
19. API: POST /api/hunting/query/execute returns refuted hypothesis on zero telemetry match.
20. API: POST /api/hunting/query/execute provides contextual follow-up query guidance.
21. API: POST /api/hunting/chain/reconstruct reconstructs multi-stage attack chain.
22. API: POST /api/hunting/chain/reconstruct flags telemetry gaps and inferred steps.
23. API: POST /api/soc/playbooks/{id}/execute executes containment with capability token.
24. API: POST /api/soc/playbooks/{id}/execute rejects prefix-spoofed capability tokens.
25. End-to-End Lifecycle: Telemetry Ingest -> Threat Detection -> ATT&CK Mapping -> Threat Hunt -> Attack Chain -> Playbook Approval -> Capability Execution.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from redloop.assessment.soc_playbooks import PlaybookApprovalStore, PlaybookStepStatus, SOCPlaybookEngine



@pytest.fixture
def p6_client(tmp_path):
    """Test client with isolated SQLite audit database and fresh engines."""
    db_file = tmp_path / "p6_audit.db"
    store = PlaybookApprovalStore(db_path=db_file)
    PlaybookApprovalStore._instance = store
    SOCPlaybookEngine._reset_playbooks()
    from fastapi import FastAPI
    from redloop.workbench import register_workbench_routes
    from redloop.assessment.soar_engine import get_or_create_operator_token
    token, _ = get_or_create_operator_token()
    app = FastAPI()
    register_workbench_routes(app, db_path=str(db_file), scope_manager=None)
    client = TestClient(app, base_url="http://testserver", headers={"X-Operator-Token": token})
    return client


# =========================================================================
# Scenario 1 - 7: MITRE ATT&CK Intelligence & Heatmap APIs
# =========================================================================

def test_01_api_attack_tactics(p6_client):
    """Scenario 1: GET /api/hunting/attack/tactics returns 14 Enterprise tactics."""
    res = p6_client.get("/api/hunting/attack/tactics")
    assert res.status_code == 200
    tactics = res.json()["tactics"]
    assert len(tactics) == 14
    tac_ids = [t["tactic_id"] for t in tactics]
    assert "TA0001" in tac_ids
    assert "TA0040" in tac_ids


def test_02_api_attack_techniques(p6_client):
    """Scenario 2: GET /api/hunting/attack/techniques returns catalog techniques."""
    res = p6_client.get("/api/hunting/attack/techniques")
    assert res.status_code == 200
    techs = res.json()["techniques"]
    assert len(techs) >= 20
    t_ids = [t["technique_id"] for t in techs]
    assert "T1059.001" in t_ids
    assert "T1190" in t_ids


def test_03_api_attack_techniques_filter(p6_client):
    """Scenario 3: GET /api/hunting/attack/techniques?tactic_id=TA0002 filters by tactic."""
    res = p6_client.get("/api/hunting/attack/techniques?tactic_id=TA0002")
    assert res.status_code == 200
    techs = res.json()["techniques"]
    assert len(techs) >= 3
    for t in techs:
        assert "TA0002" in t["tactic_ids"]


def test_04_api_attack_map_events(p6_client):
    """Scenario 4: POST /api/hunting/attack/map maps security events to ATT&CK."""
    event_data = {
        "event_id": "ev-map-1",
        "timestamp": "2026-11-04T12:00:00Z",
        "source_type": "windows_sysmon",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -w hidden -enc JABz...",
        "hostname": "WS-01",
    }
    res = p6_client.post(
        "/api/hunting/attack/map",
        json={"events": [event_data]},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    mappings = res.json()["mappings"]
    assert len(mappings) >= 1
    assert mappings[0]["technique_id"] == "T1059.001"
    assert mappings[0]["tactic_id"] == "TA0002"


def test_05_api_attack_map_alerts(p6_client):
    """Scenario 5: POST /api/hunting/attack/map maps SOC alerts to ATT&CK."""
    alert_data = {
        "alert_id": "alt-test-1",
        "rule_id": "SEC-WEB-001",
        "title": "SQL Injection Detected",
        "severity": "HIGH",
        "confidence": 0.90,
        "matched_event_ids": ["e1"],
        "target_ip": "10.0.0.50",
    }
    res = p6_client.post(
        "/api/hunting/attack/map",
        json={"alerts": [alert_data]},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    mappings = res.json()["mappings"]
    assert len(mappings) >= 1
    assert mappings[0]["technique_id"] == "T1190"
    assert mappings[0]["tactic_id"] == "TA0001"


def test_06_api_attack_matrix_json(p6_client):
    """Scenario 6: GET /api/hunting/attack/matrix returns JSON matrix heatmap."""
    res = p6_client.get("/api/hunting/attack/matrix")
    assert res.status_code == 200
    matrix = res.json()["matrix"]
    assert matrix["total_tactics"] == 14
    assert "tactics_breakdown" in matrix


def test_07_api_attack_matrix_markdown(p6_client):
    """Scenario 7: GET /api/hunting/attack/matrix?format=markdown returns Markdown report."""
    res = p6_client.get("/api/hunting/attack/matrix?format=markdown")
    assert res.status_code == 200
    assert "text/markdown" in res.headers["content-type"]
    assert "# REDLOOP MITRE ATT&CK Matrix Coverage Report" in res.text


# =========================================================================
# Scenario 8 - 14: Sigma Detection Engineering & Validation APIs
# =========================================================================

def test_08_api_sigma_matrix(p6_client):
    """Scenario 8: GET /api/hunting/sigma/matrix returns formal Sigma support matrix."""
    res = p6_client.get("/api/hunting/sigma/matrix")
    assert res.status_code == 200
    mat = res.json()["matrix"]
    assert "supported_modifiers" in mat
    assert "contains" in mat["supported_modifiers"]


def test_09_api_sigma_validate_success(p6_client):
    """Scenario 9: POST /api/hunting/sigma/validate validates valid Sigma rule."""
    valid_yaml = """
title: Suspicious Cmd Execution
id: 11111111-2222-3333-4444-555555555555
status: stable
description: Tests cmd execution
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: 'cmd.exe'
    condition: selection
level: medium
"""
    res = p6_client.post(
        "/api/hunting/sigma/validate",
        json={"rule_yaml": valid_yaml},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["rule_id"] == "11111111-2222-3333-4444-555555555555"


def test_10_api_sigma_validate_bad_yaml(p6_client):
    """Scenario 10: POST /api/hunting/sigma/validate rejects malformed YAML."""
    res = p6_client.post(
        "/api/hunting/sigma/validate",
        json={"rule_yaml": "title: [unbalanced list"},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["is_valid"] is False
    assert len(res.json()["errors"]) > 0


def test_11_api_sigma_validate_missing_fields(p6_client):
    """Scenario 11: POST /api/hunting/sigma/validate rejects missing required fields."""
    incomplete = "title: Only Title\nid: test-id"
    res = p6_client.post(
        "/api/hunting/sigma/validate",
        json={"rule_yaml": incomplete},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["is_valid"] is False
    assert any("logsource" in e for e in res.json()["errors"])


def test_12_api_sigma_validate_redos(p6_client):
    """Scenario 12: POST /api/hunting/sigma/validate blocks ReDoS patterns."""
    redos_rule = """
title: ReDoS Rule
id: redos-1
status: experimental
description: ReDoS test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '^(a+)+$'
    condition: selection
"""
    res = p6_client.post(
        "/api/hunting/sigma/validate",
        json={"rule_yaml": redos_rule},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["is_valid"] is False
    assert any("redos" in e.lower() for e in res.json()["errors"])


def test_13_api_sigma_test_supplied_events(p6_client):
    """Scenario 13: POST /api/hunting/sigma/test evaluates rule against payload events."""
    rule_yaml = """
title: Cmd Execution
id: test-sig-01
status: stable
description: Cmd execution
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: 'cmd.exe'
    condition: selection
level: high
"""
    event_data = {
        "event_id": "e-sig-1",
        "timestamp": "2026-11-04T12:00:00Z",
        "source_type": "windows_sysmon",
        "process_name": "C:\\Windows\\System32\\cmd.exe",
    }
    res = p6_client.post(
        "/api/hunting/sigma/test",
        json={"rule_yaml": rule_yaml, "events": [event_data]},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_matched"] == 1
    assert data["matches"][0]["matched_event_id"] == "e-sig-1"


def test_14_api_sigma_test_live_ingested_events(p6_client, tmp_path):
    """Scenario 14: POST /api/hunting/sigma/test evaluates rule against live ingested events."""
    # 1. Ingest Linux auth event
    log_file = tmp_path / "auth_test.log"
    log_file.write_text("Oct 24 14:16:00 web01 sudo[12350]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow\n")
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "linux_auth"},
        headers={"Origin": "http://testserver"},
    )

    # 2. Test rule matching shadow access
    rule_yaml = """
title: Shadow File Access
id: shadow-rule-01
status: stable
description: Shadow access
logsource:
    category: syslog
detection:
    selection:
        CommandLine|contains: '/etc/shadow'
    condition: selection
level: critical
"""
    res = p6_client.post(
        "/api/hunting/sigma/test",
        json={"rule_yaml": rule_yaml},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["total_matched"] >= 1


# =========================================================================
# Scenario 15 - 20: Threat Hunting Query & Hypothesis APIs
# =========================================================================

def test_15_api_hunting_query_plan(p6_client):
    """Scenario 15: POST /api/hunting/query/plan returns explainable query plan."""
    res = p6_client.post(
        "/api/hunting/query/plan",
        json={"query": "Hunt for powershell from 192.168.1.50 in last 24 hours", "limit": 50},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    plan = res.json()["plan"]
    assert plan["safety_checks_passed"] is True
    assert plan["limit"] == 50
    assert len(plan["filter_clauses"]) >= 2


def test_16_api_hunting_query_plan_cost(p6_client):
    """Scenario 16: POST /api/hunting/query/plan estimates execution cost."""
    # Broad query past 30 days -> MEDIUM / HIGH
    res = p6_client.post(
        "/api/hunting/query/plan",
        json={"query": "Search all events in last 30 days", "limit": 500},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    plan = res.json()["plan"]
    assert plan["estimated_cost"] in ("MEDIUM", "HIGH")


def test_17_api_hunting_query_plan_limit_clamping(p6_client):
    """Scenario 17: POST /api/hunting/query/plan clamps excessive limits to 1000."""
    res = p6_client.post(
        "/api/hunting/query/plan",
        json={"query": "Search web events", "limit": 999999},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["plan"]["limit"] == 1000


def test_18_api_hunting_query_execute_confirmed(p6_client, tmp_path):
    """Scenario 18: POST /api/hunting/query/execute finds matching telemetry and confirms hypothesis."""
    # Ingest web log
    log_file = tmp_path / "web_hunt.log"
    log_file.write_text('198.51.100.99 - - [10/Oct/2026:13:56:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 120\n')
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )

    res = p6_client.post(
        "/api/hunting/query/execute",
        json={"query": "Hunt for SQL injection from 198.51.100.99"},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    result = res.json()["result"]
    assert result["hypothesis_status"] == "CONFIRMED"
    assert result["total_matched"] >= 1
    assert "198.51.100.99" in result["matched_entities"]["ips"]


def test_19_api_hunting_query_execute_refuted(p6_client, tmp_path):
    """Scenario 19: POST /api/hunting/query/execute returns refuted hypothesis when not found."""
    # Ingest multiple non-matching records
    log_file = tmp_path / "clean_hunt.log"
    log_file.write_text("\n".join([f'10.0.0.{i} - - [10/Oct/2026:13:55:00 +0000] "GET /index.html HTTP/1.1" 200 100' for i in range(10)]) + "\n")
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )

    res = p6_client.post(
        "/api/hunting/query/execute",
        json={"query": "Hunt for powershell from 192.168.1.99"},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    assert res.json()["result"]["hypothesis_status"] in ("REFUTED", "INCONCLUSIVE")
    assert res.json()["result"]["total_matched"] == 0


def test_20_api_hunting_query_execute_followups(p6_client, tmp_path):
    """Scenario 20: POST /api/hunting/query/execute provides contextual follow-up query suggestions."""
    log_file = tmp_path / "fu_hunt.log"
    log_file.write_text('10.0.0.88 - - [10/Oct/2026:13:56:00 +0000] "GET /test.php?id=1%20UNION%20SELECT%201 HTTP/1.1" 500 100\n')
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )

    res = p6_client.post(
        "/api/hunting/query/execute",
        json={"query": "Hunt for SQL from 10.0.0.88"},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    followups = res.json()["result"]["suggested_followups"]
    assert len(followups) > 0


# =========================================================================
# Scenario 21 - 22: Attack-Chain Reconstruction APIs
# =========================================================================

def test_21_api_chain_reconstruct_multi_stage(p6_client, tmp_path):
    """Scenario 21: POST /api/hunting/chain/reconstruct builds multi-stage attack chain."""
    # Ingest web attack and run detection
    log_file = tmp_path / "chain_log.log"
    log_file.write_text('198.51.100.4 - - [10/Oct/2026:13:56:00 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 403 0\n')
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )
    p6_client.post("/api/soc/detect", headers={"Origin": "http://testserver"})

    res = p6_client.post(
        "/api/hunting/chain/reconstruct",
        json={"title": "Perimeter Breach Investigation"},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    chain = res.json()["chain"]
    assert chain["title"] == "Perimeter Breach Investigation"
    assert len(chain["steps"]) >= 1


def test_22_api_chain_reconstruct_telemetry_gaps(p6_client, tmp_path):
    """Scenario 22: POST /api/hunting/chain/reconstruct flags telemetry gaps."""
    # Ingest only sudo command without initial access
    log_file = tmp_path / "sudo_only.log"
    log_file.write_text("Oct 24 14:16:00 web01 sudo[12350]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow\n")
    p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "linux_auth"},
        headers={"Origin": "http://testserver"},
    )

    res = p6_client.post(
        "/api/hunting/chain/reconstruct",
        json={},
        headers={"Origin": "http://testserver"},
    )
    assert res.status_code == 200
    gaps = res.json()["chain"]["telemetry_gaps"]
    assert len(gaps) >= 1


# =========================================================================
# Scenario 23 - 24: Playbook Execution API with Capability Token Enforcement
# =========================================================================

def test_23_api_playbook_execute_capability_token(p6_client):
    """Scenario 23: POST /api/soc/playbooks/{id}/execute executes step with capability token."""
    # 1. Approve step to obtain capability token
    res_app = p6_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={"step_id": "step-cred-2", "approver": "sec_lead", "approved": True},
        headers={"Origin": "http://testserver"},
    )
    assert res_app.status_code == 200
    cap_token = res_app.json()["capability_token"]
    assert cap_token.startswith("rl-cap-")

    # 2. Execute step using capability token
    res_exec = p6_client.post(
        "/api/soc/playbooks/PB-CRED/execute",
        json={"step_id": "step-cred-2", "capability_token": cap_token, "operator": "sec_operator_bob"},
        headers={"Origin": "http://testserver"},
    )
    assert res_exec.status_code == 200
    assert res_exec.json()["status"] == "EXECUTED"


def test_24_api_playbook_execute_prefix_spoof_rejected(p6_client):
    """Scenario 24: POST /api/soc/playbooks/{id}/execute rejects prefix-spoofed tokens."""
    # Approve step
    p6_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={"step_id": "step-cred-2", "approver": "sec_lead", "approved": True},
        headers={"Origin": "http://testserver"},
    )

    # Attacker supplies arbitrary prefix string
    res_exec_bad = p6_client.post(
        "/api/soc/playbooks/PB-CRED/execute",
        json={"step_id": "step-cred-2", "capability_token": "rl-cap-spoofed-token-xyz"},
        headers={"Origin": "http://testserver"},
    )
    assert res_exec_bad.status_code == 403
    assert "Invalid or unrecognized" in res_exec_bad.json()["detail"]


# =========================================================================
# Scenario 25: Full End-to-End Integrated Lifecycle
# =========================================================================

def test_25_full_e2e_platform_lifecycle(p6_client, tmp_path):
    """Scenario 25: Full lifecycle: Ingest -> Detect -> ATT&CK Map -> Hunt -> Chain -> Approve -> Execute."""
    # 1. INGESTION: Ingest web attack log
    log_file = tmp_path / "e2e_web.log"
    log_file.write_text('198.51.100.50 - - [10/Oct/2026:13:56:00 +0000] "GET /api/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 120\n')
    res_ingest = p6_client.post(
        "/api/soc/ingest",
        json={"file_path": str(log_file), "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )
    assert res_ingest.status_code == 200

    # 2. DETECTION: Run automated detections to trigger alerts
    res_detect = p6_client.post("/api/soc/detect", headers={"Origin": "http://testserver"})
    assert res_detect.status_code == 200
    alerts = res_detect.json()["alerts"]
    assert len(alerts) >= 1

    # 3. ATT&CK MAPPING: Map detected alerts to ATT&CK matrix
    res_map = p6_client.post(
        "/api/hunting/attack/map",
        json={"alerts": alerts},
        headers={"Origin": "http://testserver"},
    )
    assert res_map.status_code == 200
    assert len(res_map.json()["mappings"]) >= 1

    # 4. THREAT HUNTING: Execute hypothesis hunt for lateral movement
    res_hunt = p6_client.post(
        "/api/hunting/query/execute",
        json={"query": "Hunt for SQL injection from 198.51.100.50"},
        headers={"Origin": "http://testserver"},
    )
    assert res_hunt.status_code == 200
    assert res_hunt.json()["result"]["hypothesis_status"] == "CONFIRMED"

    # 5. ATTACK CHAIN: Reconstruct correlated progression
    res_chain = p6_client.post(
        "/api/hunting/chain/reconstruct",
        json={"title": "E2E Investigation Attack Chain"},
        headers={"Origin": "http://testserver"},
    )
    assert res_chain.status_code == 200
    assert len(res_chain.json()["chain"]["steps"]) >= 1

    # 6. PLAYBOOK APPROVAL: Approve perimeter blocking response step
    res_app = p6_client.post(
        "/api/soc/playbooks/PB-WEB/approve",
        json={"step_id": "step-web-2", "approver": "soc_lead_dave", "approved": True},
        headers={"Origin": "http://testserver"},
    )
    assert res_app.status_code == 200
    cap_token = res_app.json()["capability_token"]

    # 7. CAPABILITY EXECUTION: Execute containment with cryptographic capability token
    res_exec = p6_client.post(
        "/api/soc/playbooks/PB-WEB/execute",
        json={"step_id": "step-web-2", "capability_token": cap_token, "operator": "ops_frank"},
        headers={"Origin": "http://testserver"},
    )
    assert res_exec.status_code == 200
    assert res_exec.json()["status"] == "EXECUTED"
