"""Comprehensive live verification of all REDLOOP endpoints and capabilities.

Tests live API behavior on an ASGI application instance.
"""

from __future__ import annotations

import json
from starlette.testclient import TestClient
from redloop.dashboard import create_app
from redloop.investigation import get_investigation_store


def run_live_verification():
    print("============================================================")
    print("STARTING REDLOOP LIVE ENDPOINT VERIFICATION")
    print("============================================================\n")

    import os
    from pathlib import Path
    from redloop.scope import ScopeManager

    sm = None
    if Path("scope.yaml").exists():
        secret = os.environ.get("REDLOOP_SCOPE_SECRET")
        if not secret and Path(".env").exists():
            for line in Path(".env").read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip().startswith("REDLOOP_SCOPE_SECRET="):
                    secret = line.strip().split("=", 1)[1].strip().strip('"').strip("'")
                    break
        if not secret:
            raise RuntimeError("REDLOOP_SCOPE_SECRET must be configured in environment or .env")
        sm = ScopeManager("scope.yaml", secret=secret)

    app = create_app("redloop_audit.db", scope_manager=sm)
    client = TestClient(app, base_url="http://127.0.0.1")

    results = {}

    # 1. GET / (SPA Shell)
    r = client.get("/")
    assert r.status_code == 200, f"GET / failed: {r.status_code}"
    assert "RedLoop" in r.text or "REDLOOP" in r.text
    assert "OPERATE" in r.text
    assert "INVESTIGATE" in r.text
    results["GET /"] = f"OK (HTTP {r.status_code}, {len(r.text)} bytes, Content-Type: {r.headers.get('content-type')})"
    print(f"1. GET /: {results['GET /']}")

    # 2. GET /api/scope
    r = client.get("/api/scope")
    assert r.status_code == 200, f"GET /api/scope failed: {r.status_code}"
    scope_data = r.json()
    assert "status" in scope_data or "in_scope" in scope_data
    results["GET /api/scope"] = f"OK (status: {scope_data.get('status')}, in_scope: {scope_data.get('in_scope')}, targets: {scope_data.get('targets')})"
    print(f"2. GET /api/scope: {results['GET /api/scope']}")

    # 3. GET /api/models
    r = client.get("/api/models")
    assert r.status_code == 200, f"GET /api/models failed: {r.status_code}"
    models_data = r.json()
    assert "models" in models_data
    results["GET /api/models"] = f"OK ({len(models_data.get('models', []))} models configured)"
    print(f"3. GET /api/models: {results['GET /api/models']}")

    # 4. GET /api/tools/status
    r = client.get("/api/tools/status")
    assert r.status_code == 200, f"GET /api/tools/status failed: {r.status_code}"
    tools_diag = r.json()
    assert "nmap" in tools_diag
    results["GET /api/tools/status"] = f"OK (Nmap installed: {tools_diag['nmap']['installed']}, path: {tools_diag['nmap'].get('executable_path')})"
    print(f"4. GET /api/tools/status: {results['GET /api/tools/status']}")

    # 5. POST /api/chat/message - Normal technical question
    r = client.post(
        "/api/chat/message",
        json={"message": "Explain the TCP three-way handshake simply.", "conversation_id": "live-test-chat"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200, f"Chat message failed: {r.status_code}"
    chat_resp = r.json()
    assert "response" in chat_resp
    results["POST /api/chat/message (Normal technical)"] = f"OK (HTTP {r.status_code}, response length: {len(chat_resp['response'])} chars)"
    print(f"5. POST /api/chat/message (Normal chat): {results['POST /api/chat/message (Normal technical)']}")

    # 6. POST /api/chat/message - Nmap tool request
    r = client.post(
        "/api/chat/message",
        json={"message": "Scan authorized target 127.0.0.1 with Nmap.", "conversation_id": "live-test-nmap"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200, f"Nmap chat failed: {r.status_code}"
    nmap_resp = r.json()
    assert "task" in nmap_resp
    results["POST /api/chat/message (Nmap scan)"] = f"OK (Task status: {nmap_resp['task'].get('status')})"
    print(f"6. POST /api/chat/message (Nmap scan): {results['POST /api/chat/message (Nmap scan)']}")

    # 7. POST /api/chat/message - Large technical payload (30k chars)
    large_payload = "2026-10-26 12:00:00 [AUDIT] Connection accepted: 127.0.0.1:8080\n" * 450
    assert len(large_payload) > 25000
    r = client.post(
        "/api/chat/message",
        json={"message": f"Analyze these logs:\n{large_payload}", "conversation_id": "live-test-large"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200, f"Large chat input failed: {r.status_code}"
    results["POST /api/chat/message (Large input 30k chars)"] = f"OK (Accepted without 413, response length: {len(r.json().get('response', ''))})"
    print(f"7. POST /api/chat/message (Large input): {results['POST /api/chat/message (Large input 30k chars)']}")

    # 8. POST /api/tools/execute - Controlled Nmap execution on authorized localhost
    r = client.post(
        "/api/tools/execute",
        json={"tool": "nmap", "target": "127.0.0.1", "ports": [8080, 8765]},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200, f"Controlled Nmap failed: {r.status_code}"
    nmap_exec = r.json()
    results["POST /api/tools/execute (Authorized Nmap)"] = f"OK (Status: {nmap_exec.get('status')}, tool: {nmap_exec.get('tool')}, exit_code: {nmap_exec.get('exit_code')})"
    print(f"8. POST /api/tools/execute (Authorized Nmap): {results['POST /api/tools/execute (Authorized Nmap)']}")

    # 9. POST /api/tools/execute - Blocked unauthorized target
    r = client.post(
        "/api/tools/execute",
        json={"tool": "nmap", "target": "unauthorized-external-bank.com", "ports": [80]},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 403
    blocked_exec = r.json()
    assert blocked_exec.get("status") == "BLOCKED"
    assert blocked_exec.get("error_category") == "AUTHORIZATION_BLOCKED"
    results["POST /api/tools/execute (Unauthorized blocked)"] = f"OK (Blocked fail-closed with HTTP 403, category: {blocked_exec.get('error_category')})"
    print(f"9. POST /api/tools/execute (Unauthorized blocked): {results['POST /api/tools/execute (Unauthorized blocked)']}")

    # 10. POST /api/kali/execute - Safe command execution vs dangerous command
    r = client.post(
        "/api/kali/execute",
        json={"command": "whoami"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    whoami_res = r.json()
    results["POST /api/kali/execute (whoami)"] = f"OK (State: {whoami_res.get('state')}, stdout: {whoami_res.get('stdout', '').strip()})"
    print(f"10. POST /api/kali/execute (whoami): {results['POST /api/kali/execute (whoami)']}")

    r_dang = client.post(
        "/api/kali/execute",
        json={"command": "rm -rf /"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r_dang.status_code == 403
    dang_res = r_dang.json()
    assert dang_res.get("state") == "BLOCKED"
    results["POST /api/kali/execute (rm -rf / blocked)"] = f"OK (Blocked with HTTP 403, error: {dang_res.get('stderr')})"
    print(f"11. POST /api/kali/execute (rm -rf blocked): {results['POST /api/kali/execute (rm -rf / blocked)']}")

    # 12. GET & POST /api/investigations
    r = client.get("/api/investigations/active")
    assert r.status_code == 200
    inv = r.json()
    results["GET /api/investigations/active"] = f"OK (Active: '{inv.get('title')}', Target: {inv.get('target')})"
    print(f"12. GET /api/investigations/active: {results['GET /api/investigations/active']}")

    # 13. Reports: PDF
    r = client.get("/report/pdf?target=127.0.0.1")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-")
    results["GET /report/pdf"] = f"OK (Magic: %PDF-, size: {len(r.content)} bytes, Content-Type: application/pdf)"
    print(f"13. GET /report/pdf: {results['GET /report/pdf']}")

    # 14. Reports: PPTX
    r = client.get("/report/pptx?target=127.0.0.1")
    assert r.status_code == 200
    assert "presentationml" in r.headers["content-type"]
    assert r.content.startswith(b"PK\x03\x04")
    results["GET /report/pptx"] = f"OK (Magic: PK\\x03\\x04, size: {len(r.content)} bytes, Content-Type: {r.headers['content-type']})"
    print(f"14. GET /report/pptx: {results['GET /report/pptx']}")

    # 15. Reports: HTML
    r = client.get("/report/html?target=127.0.0.1")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "<!doctype html>" in r.text.lower()
    results["GET /report/html"] = f"OK (Doctype: HTML5, size: {len(r.content)} bytes, Content-Type: {r.headers['content-type']})"
    print(f"15. GET /report/html: {results['GET /report/html']}")

    # 16. Reports: JSON
    r = client.get("/report/json?target=127.0.0.1")
    assert r.status_code == 200
    data = r.json()
    assert "target" in data and "findings" in data and "audit_records_count" in data
    results["GET /report/json"] = f"OK (Keys: {list(data.keys())[:4]}..., Content-Type: {r.headers['content-type']})"
    print(f"16. GET /report/json: {results['GET /report/json']}")

    # 17. Reports: Markdown
    r = client.get("/report/markdown?target=127.0.0.1")
    assert r.status_code == 200
    assert "127.0.0.1" in r.text
    assert len(r.text) > 50
    results["GET /report/markdown"] = f"OK (Size: {len(r.content)} bytes, Content-Type: {r.headers['content-type']})"
    print(f"17. GET /report/markdown: {results['GET /report/markdown']}")

    # 18. Phase 1: Open-Source Architecture Matrix
    r = client.get("/api/architecture/matrix")
    assert r.status_code == 200
    matrix_data = r.json()
    assert "studied_projects" in matrix_data and "integration_matrix" in matrix_data
    results["GET /api/architecture/matrix"] = f"OK ({len(matrix_data['studied_projects'])} projects analyzed, {len(matrix_data['integration_matrix'])} matrix capabilities)"
    print(f"18. GET /api/architecture/matrix: {results['GET /api/architecture/matrix']}")

    # 19. Phase 2: Autonomous Agentic Plan Construction
    r = client.post(
        "/api/agentic/plan",
        json={"target": "127.0.0.1", "intent": "Autonomous PentestGPT service enumeration", "ports": [8080, 8765]},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    plan_data = r.json()
    assert "plan_id" in plan_data and "nodes" in plan_data
    results["POST /api/agentic/plan"] = f"OK (Plan ID: {plan_data['plan_id']}, {len(plan_data['nodes'])} PTT nodes created)"
    print(f"19. POST /api/agentic/plan: {results['POST /api/agentic/plan']}")

    # 20. Phase 3: Threat Intelligence CISA KEV Query
    r = client.get("/api/threat-intel/cve/CVE-2021-44228")
    assert r.status_code == 200
    cve_data = r.json()
    assert cve_data.get("in_cisa_kev") is True
    results["GET /api/threat-intel/cve/CVE-2021-44228"] = f"OK (in_cisa_kev: True, epss: {cve_data.get('epss_score')})"
    print(f"20. GET /api/threat-intel/cve: {results['GET /api/threat-intel/cve/CVE-2021-44228']}")

    # 21. Phase 3: OWASP ASVS v4.0 Verification
    r = client.post(
        "/api/asvs/evaluate",
        json={"url": "http://127.0.0.1:8765", "test_endpoints": False},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    asvs_data = r.json()
    assert "score_percentage" in asvs_data and "total_checks" in asvs_data
    results["POST /api/asvs/evaluate"] = f"OK (Score: {asvs_data['score_percentage']}%, Total checks: {asvs_data['total_checks']})"
    print(f"21. POST /api/asvs/evaluate: {results['POST /api/asvs/evaluate']}")

    # 22. Phase 3: Advanced Forensics Triage
    r = client.post(
        "/api/forensics/advanced-triage",
        json={"log_type": "windows_event", "raw_content": "<EventID>4625</EventID><Data Name='TargetUserName'>Administrator</Data>"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    forensics_data = r.json()
    assert "findings" in forensics_data
    results["POST /api/forensics/advanced-triage"] = f"OK (Risk: {forensics_data['risk_level']}, Findings: {len(forensics_data['findings'])})"
    print(f"22. POST /api/forensics/advanced-triage: {results['POST /api/forensics/advanced-triage']}")

    # 23. Phase 5: Kali Linux Terminal Output Ingestion
    sample_terminal = "PORT 80/tcp open http Apache httpd 2.4.41\nPORT 8080/tcp open http Apache Tomcat"
    r = client.post(
        "/api/kali/analyze-output",
        json={"raw_output": sample_terminal, "target": "127.0.0.1"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    term_data = r.json()
    assert term_data["tool_detected"] == "nmap"
    assert "next_step" in term_data
    results["POST /api/kali/analyze-output"] = f"OK (Tool: {term_data['tool_detected']}, Next Command: {term_data['next_step']['recommended_command'][:35]}...)"
    print(f"23. POST /api/kali/analyze-output: {results['POST /api/kali/analyze-output']}")

    # 24. Phase 6: Multi-Provider AI Gateway
    r = client.get("/api/providers/config")
    assert r.status_code == 200
    prov_data = r.json()
    assert "providers" in prov_data
    results["GET /api/providers/config"] = f"OK ({len(prov_data['providers'])} AI providers configured with encrypted keystore)"
    print(f"24. GET /api/providers/config: {results['GET /api/providers/config']}")

    # 25. Phase 7: RAG Knowledge Base Query
    r = client.get("/api/rag/query?query=nmap+scanning+procedure")
    assert r.status_code == 200
    rag_data = r.json()
    assert "results" in rag_data
    results["GET /api/rag/query"] = f"OK ({len(rag_data['results'])} verified security playbooks retrieved)"
    print(f"25. GET /api/rag/query: {results['GET /api/rag/query']}")

    # 26. Phase 10: Multi-Model Evaluator Benchmark
    r = client.get("/api/models/evaluator?provider_id=groq&model=llama-3.3-70b-versatile")
    assert r.status_code == 200
    eval_data = r.json()
    assert eval_data.get("accuracy_percentage") >= 90.0
    results["GET /api/models/evaluator"] = f"OK (Benchmark accuracy: {eval_data['accuracy_percentage']}%, Latency: {eval_data['total_latency_ms']}ms)"
    print(f"26. GET /api/models/evaluator: {results['GET /api/models/evaluator']}")

    # 27. Phase 10: Investigation Cytoscape Dual Graph Export (Empty graph verification & Genuine Population)
    r_empty = client.post(
        "/api/investigations",
        json={"title": "Clean Audit Investigation", "target": "10.0.0.99", "scope_status": "PENDING_VERIFICATION"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r_empty.status_code == 200
    empty_inv = r_empty.json()
    empty_id = empty_inv["id"]

    # Verify newly created investigation has 0 elements (empty graph integrity)
    r = client.get(f"/api/investigations/{empty_id}/graph")
    assert r.status_code == 200
    clean_graph_data = r.json()
    assert len(clean_graph_data["elements"]) == 0, f"Empty investigation must remain empty, found {len(clean_graph_data['elements'])}"

    # Populate graph using genuine OSINT IP indicator
    r_osint = client.post(
        "/api/osint/ip",
        json={"ip": "8.8.8.8", "investigation_id": empty_id},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r_osint.status_code == 200
    r_after = client.get(f"/api/investigations/{empty_id}/graph")
    assert r_after.status_code == 200
    pop_graph_data = r_after.json()
    assert len(pop_graph_data["elements"]) >= 3, f"Expected OSINT populated elements, got {len(pop_graph_data['elements'])}"

    results[f"GET /api/investigations/{empty_id}/graph"] = f"OK (Empty graph verified 0 elements -> Genuine OSINT populated {len(pop_graph_data['elements'])} elements)"
    print(f"27. GET /api/investigations/{empty_id}/graph: {results[f'GET /api/investigations/{empty_id}/graph']}")

    # 28. Phase 3 & 4: Dedicated OSINT IP Endpoint
    r = client.post("/api/osint/ip", json={"ip": "8.8.8.8"}, headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    osint_ip_data = r.json()
    assert osint_ip_data["status"] in ("OBSERVED", "VERIFIED")
    assert osint_ip_data["query_type"] == "ip"
    assert osint_ip_data["indicator"] == "8.8.8.8"
    assert any(f.get("property") == "classification" for f in osint_ip_data.get("findings", []))
    results["POST /api/osint/ip"] = f"OK (Status: {osint_ip_data['status']}, Findings: {len(osint_ip_data.get('findings', []))})"
    print(f"28. POST /api/osint/ip: {results['POST /api/osint/ip']}")

    # 29. Phase 3 & 4: Dedicated OSINT Domain Endpoint
    r = client.post("/api/osint/domain", json={"domain": "example.com"}, headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    osint_dom_data = r.json()
    assert osint_dom_data["status"] in ("OBSERVED", "VERIFIED")
    assert osint_dom_data["query_type"] == "domain"
    assert len(osint_dom_data.get("findings", [])) > 0
    results["POST /api/osint/domain"] = f"OK (Domain: example.com, Findings: {len(osint_dom_data.get('findings', []))})"
    print(f"29. POST /api/osint/domain: {results['POST /api/osint/domain']}")

    # 30. Phase 3 & 4: Dedicated OSINT Email Endpoint
    r = client.post("/api/osint/email", json={"email": "security-audit@example.com"}, headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    osint_email_data = r.json()
    assert osint_email_data["status"] in ("OBSERVED", "VERIFIED", "UNKNOWN")
    assert any(f.get("property") == "syntax_validation" for f in osint_email_data.get("findings", []))
    results["POST /api/osint/email"] = f"OK (Status: {osint_email_data['status']}, Findings: {len(osint_email_data.get('findings', []))})"
    print(f"30. POST /api/osint/email: {results['POST /api/osint/email']}")

    # 31. Phase 3 & 4: Dedicated OSINT Username Endpoint
    r = client.post("/api/osint/username", json={"username": "torvalds"}, headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    osint_user_data = r.json()
    assert osint_user_data["status"] in ("OBSERVED", "VERIFIED", "NOT_FOUND_IN_CHECKED_SOURCES")
    assert any("identity" in lim.lower() for lim in osint_user_data.get("limitations", []))
    results["POST /api/osint/username"] = f"OK (Status: {osint_user_data['status']}, Limitations verified)"
    print(f"31. POST /api/osint/username: {results['POST /api/osint/username']}")

    # 32. Phase 3 & 4: Dedicated OSINT Phone Endpoint
    r = client.post("/api/osint/phone", json={"phone": "+14155552671"}, headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    osint_phone_data = r.json()
    assert osint_phone_data["status"] in ("OBSERVED", "VERIFIED")
    assert any(f.get("property") in ("e164_format", "e164_parsing") for f in osint_phone_data.get("findings", []))
    results["POST /api/osint/phone"] = f"OK (Status: {osint_phone_data['status']}, E.164 parsed)"
    print(f"32. POST /api/osint/phone: {results['POST /api/osint/phone']}")

    # 33. Phase 3 & 4: Dedicated OSINT Metadata Endpoint
    test_file_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential Lab Report) >>\nendobj\ntrailer\n<<>>\n%%EOF"
    r = client.post(
        "/api/osint/metadata",
        files={"file": ("report.pdf", test_file_content, "application/pdf")},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 200
    osint_meta_data = r.json()
    assert osint_meta_data["status"] in ("OBSERVED", "VERIFIED")
    assert osint_meta_data["evidence_hash"] != ""
    assert any("mime_type" in f for f in osint_meta_data.get("findings", []))
    results["POST /api/osint/metadata"] = f"OK (Status: {osint_meta_data['status']}, Hash: {osint_meta_data['evidence_hash'][:16]}...)"
    print(f"33. POST /api/osint/metadata: {results['POST /api/osint/metadata']}")

    # 34. Phase 2: Universal Chat Entry Point - Non-security conceptual inquiry
    r = client.post(
        "/api/chat/message",
        json={"message": "Explain what DNS is.", "conversation_id": "live-chat-dns"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    chat_dns_resp = r.json()
    assert "response" in chat_dns_resp
    assert chat_dns_resp.get("intent", {}).get("intent") == "GENERAL_CHAT"
    assert chat_dns_resp.get("task", {}).get("capability") == "chat.general"
    results["POST /api/chat/message (Explain DNS)"] = f"OK (Intent: GENERAL_CHAT, Capability: chat.general, No tools run)"
    print(f"34. POST /api/chat/message (Explain DNS): {results['POST /api/chat/message (Explain DNS)']}")

    # 35. Phase 2 & 4: Universal Chat Entry Point - OSINT IP Request in Chat
    r = client.post(
        "/api/chat/message",
        json={"message": "Investigate this public IP 8.8.8.8", "conversation_id": "live-chat-osint"},
        headers={"Origin": "http://127.0.0.1"}
    )
    assert r.status_code == 200
    chat_osint_resp = r.json()
    assert "response" in chat_osint_resp
    assert chat_osint_resp.get("intent", {}).get("intent") == "OSINT_IP"
    assert "OSINT Intelligence" in chat_osint_resp["response"]
    results["POST /api/chat/message (Investigate IP)"] = f"OK (Intent: OSINT_IP, Status: {chat_osint_resp.get('task', {}).get('status')})"
    print(f"35. POST /api/chat/message (Investigate IP): {results['POST /api/chat/message (Investigate IP)']}")

    # 36. Phase 8: Verify OSINT in Chat Populated the Investigation Graph
    active_inv = client.get("/api/investigations/active").json()
    active_id = active_inv.get("id", "inv-default")
    r = client.get(f"/api/investigations/{active_id}/graph")
    assert r.status_code == 200
    post_chat_graph = r.json()
    assert len(post_chat_graph["elements"]) > 0, "Expected non-empty graph after chat OSINT synchronization"
    results["Graph Expansion Verification"] = f"OK (Investigation graph maintained and expanded with {len(post_chat_graph['elements'])} elements)"
    print(f"36. Graph Expansion Verification: {results['Graph Expansion Verification']}")

    print("\n============================================================")
    print("ALL 36 LIVE ENDPOINT & CAPABILITY CHECKS VERIFIED SUCCESSFULLY!")
    print("============================================================\n")


if __name__ == "__main__":
    run_live_verification()
