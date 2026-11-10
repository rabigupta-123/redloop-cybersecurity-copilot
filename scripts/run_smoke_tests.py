import asyncio
import json
import sqlite3
import tempfile
import time
from pathlib import Path

import httpx

from redloop.audit import AuditLogger
from redloop.assessment.scope_guard import AssessmentScopeGuard
import datetime
import yaml
from redloop.scope import ScopeManager, sign_scope
from redloop.connectors.mcp_server import RedloopMCPServer
from redloop.dashboard import create_app
from redloop.assessment.orchestrator import TaskOrchestrator

# Setup temporary audit DB and scope manager with signed contract
tmp_dir = tempfile.mkdtemp()
db_path = Path(tmp_dir) / "smoke_audit.sqlite"
audit = AuditLogger(str(db_path))

# In-scope: 127.0.0.1 and scanme.nmap.org
# Out-of-scope: 192.0.2.200 (TEST-NET-1 unlisted address)
signing_secret = "smoke_secret_" + "x" * 50
today = datetime.date.today().isoformat()
raw_manifest = {
    "version": 1,
    "id": "smoke-test-scope",
    "authorized_by": "Security Operations Lead",
    "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat(),
    "targets": [
        {
            "cidr": "127.0.0.1/32",
            "label": "Authorized loopback test target",
            "authorized_from": today,
            "authorized_until": today,
            "allowed_actions": ["scan", "recon", "osint"],
            "ports": [80, 443, 8765],
        },
        {
            "domain": "scanme.nmap.org",
            "label": "Authorized public reconnaissance test domain",
            "authorized_from": today,
            "authorized_until": today,
            "allowed_actions": ["recon", "osint"],
            "ports": [80, 443],
        }
    ]
}
raw_manifest["signature"] = sign_scope(raw_manifest, signing_secret)
scope_file = Path(tmp_dir) / "scope.yaml"
scope_file.write_text(yaml.safe_dump(raw_manifest), encoding="utf-8")

scope_mgr = ScopeManager(scope_file=scope_file, secret=signing_secret)
scope_guard = AssessmentScopeGuard(scope_mgr, audit=audit)

# Create FastAPI workbench application
app = create_app(str(db_path), scope_manager=scope_mgr)

transcripts = {}

import sys
print("=== SMOKE TEST 1: Real Chat Request ===", file=sys.stderr)
# 1. Real chat request
async def test_chat():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765") as client:
        req_payload = {
            "message": "What are the core differences between a reverse shell and a bind shell in network penetration testing?",
            "conversation_id": "smoke-test-conv-01"
        }
        headers = {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"}
        t0 = time.perf_counter()
        resp = await client.post("/api/chat", json=req_payload, headers=headers)
        dt = (time.perf_counter() - t0) * 1000.0
        
        raw_req = {
            "method": "POST",
            "url": "http://127.0.0.1:8765/api/chat",
            "headers": headers,
            "body": req_payload
        }
        try:
            resp_body = resp.json()
        except:
            resp_body = resp.text
            
        raw_resp = {
            "status_code": resp.status_code,
            "elapsed_ms": round(dt, 2),
            "headers": dict(resp.headers),
            "body": resp_body
        }
        return raw_req, raw_resp

chat_req, chat_resp = asyncio.run(test_chat())
transcripts["smoke_test_1_chat"] = {
    "description": "Real chat request through copilot engine",
    "request": chat_req,
    "response": chat_resp
}
print(f"Chat status: {chat_resp['status_code']}, latency: {chat_resp['elapsed_ms']}ms", file=sys.stderr)


print("\n=== SMOKE TEST 2: Real OSINT Lookup with Evidence IDs ===", file=sys.stderr)
# 2. Real OSINT lookup against authorized public target
async def test_osint():
    from redloop.osint_engine import OSINTEngine
    engine = OSINTEngine()
    target = "scanme.nmap.org"
    t0 = time.perf_counter()
    report = engine.investigate_domain(target)
    dt = (time.perf_counter() - t0) * 1000.0
    
    raw_osint = {
        "target": target,
        "elapsed_ms": round(dt, 2),
        "indicator": report.indicator,
        "query_type": report.query_type,
        "status": report.status,
        "evidence_id": report.evidence_id,
        "evidence_hash": report.evidence_hash,
        "evidence_integrity_valid": report.evidence_integrity_valid,
        "confidence": report.confidence,
        "confidence_label": report.confidence_label,
        "sources_queried": report.sources_queried,
        "observation_timestamp": report.observation_timestamp,
        "findings": [f.model_dump(mode="json") if hasattr(f, "model_dump") else str(f) for f in report.findings[:3]]
    }
    return raw_osint

osint_res = asyncio.run(test_osint())
transcripts["smoke_test_2_osint"] = {
    "description": "Real OSINT lookup against authorized domain with evidence IDs",
    "result": osint_res
}
print(f"OSINT target: {osint_res['target']}, evidence id: {osint_res['evidence_id']}, confidence: {osint_res['confidence']}", file=sys.stderr)


print("\n=== SMOKE TEST 3: Real MCP Tool Call Round-Trip ===", file=sys.stderr)
# 3. Real MCP Tool Call Round-Trip (scope_check and list_targets)
async def test_mcp():
    mcp_server = RedloopMCPServer(scope_guard=scope_guard, audit_ledger=audit)
    
    # Tool call 1: scope_check for authorized target
    t0 = time.perf_counter()
    res_scope = await mcp_server.mcp.call_tool(
        "scope_check",
        {"target": "127.0.0.1", "action": "recon", "port": 80}
    )
    # Tool call 2: list_targets
    res_list = await mcp_server.mcp.call_tool(
        "list_targets",
        {}
    )
    dt = (time.perf_counter() - t0) * 1000.0
    
    def serialize_content(content):
        return [str(c) if not hasattr(c, "text") else c.text for c in content]
    
    raw_mcp = {
        "session": "in-process official MCP Python SDK session (MCPServer)",
        "tool_call_1": {
            "name": "scope_check",
            "arguments": {"target": "127.0.0.1", "action": "recon", "port": 80},
            "is_error": res_scope.is_error,
            "content": serialize_content(res_scope.content)
        },
        "tool_call_2": {
            "name": "list_targets",
            "arguments": {},
            "is_error": res_list.is_error,
            "content": serialize_content(res_list.content)
        },
        "roundtrip_ms": round(dt, 2)
    }
    return raw_mcp

mcp_res = asyncio.run(test_mcp())
transcripts["smoke_test_3_mcp"] = {
    "description": "Real MCP Tool Call Round-Trip via MCPServer 2.x",
    "result": mcp_res
}
print(f"MCP tool scope_check content: {mcp_res['tool_call_1']['content']}", file=sys.stderr)


print("\n=== SMOKE TEST 4: Deliberately Out-of-Scope Action Attempt ===", file=sys.stderr)
# 4. Out-of-scope action attempts via REST, Chat, and MCP + Ledger Rows
unauthorized_target = "192.0.2.200"

async def test_out_of_scope():
    results = {}
    
    # 4A. REST Entry Point (Recon on unauthorized target)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765") as client:
        headers = {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"}
        rest_resp = await client.post(
            "/api/workbench/recon/run",
            json={"target": unauthorized_target, "tool": "nmap", "port": 80},
            headers=headers
        )
        try:
            rest_body = rest_resp.json()
        except:
            rest_body = rest_resp.text
            
        results["rest_out_of_scope"] = {
            "entry_point": "REST API (/api/workbench/recon/run)",
            "request": {"target": unauthorized_target, "tool": "nmap", "port": 80},
            "status_code": rest_resp.status_code,
            "response_body": rest_body
        }
    
    # 4B. Chat Entry Point (Prompt attempting scan on unauthorized target)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765") as client:
        headers = {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"}
        chat_resp = await client.post(
            "/api/chat",
            json={"message": f"Scan all ports and assess vulnerabilities on {unauthorized_target}"},
            headers=headers
        )
        try:
            chat_body = chat_resp.json()
        except:
            chat_body = chat_resp.text
            
        results["chat_out_of_scope"] = {
            "entry_point": "Chat Copilot (/api/chat)",
            "request": {"message": f"Scan all ports and assess vulnerabilities on {unauthorized_target}"},
            "status_code": chat_resp.status_code,
            "response_body": chat_body
        }

    # 4C. MCP Entry Point (scope_check and run_recon on unauthorized target)
    mcp_server = RedloopMCPServer(scope_guard=scope_guard, audit_ledger=audit)
    res_mcp_scope = await mcp_server.mcp.call_tool(
        "scope_check",
        {"target": unauthorized_target, "action": "recon", "port": 80}
    )
    res_mcp_recon = await mcp_server.mcp.call_tool(
        "run_recon",
        {"target": unauthorized_target, "port": 80, "tool": "nmap"}
    )
    def serialize_content(content):
        return [str(c) if not hasattr(c, "text") else c.text for c in content]
    results["mcp_out_of_scope"] = {
        "entry_point": "MCP Server (scope_check & run_recon)",
        "request": {"target": unauthorized_target, "port": 80, "tool": "nmap"},
        "scope_check_is_error": res_mcp_scope.is_error,
        "scope_check_content": serialize_content(res_mcp_scope.content),
        "run_recon_is_error": res_mcp_recon.is_error,
        "run_recon_content": serialize_content(res_mcp_recon.content),
    }
    
    # 4D. Fetch matching audit ledger rows from database
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, target, action, module, status, details, prev_hash, event_hash FROM audit_log ORDER BY id DESC LIMIT 10"
    )
    rows = cursor.fetchall()
    ledger_entries = []
    for r in rows:
        ledger_entries.append({
            "id": r[0],
            "timestamp": r[1],
            "target": r[2],
            "action": r[3],
            "module": r[4],
            "status": r[5],
            "details": r[6],
            "prev_hash": r[7],
            "event_hash": r[8]
        })
    results["audit_ledger_rows"] = ledger_entries
    return results

oos_res = asyncio.run(test_out_of_scope())
transcripts["smoke_test_4_out_of_scope"] = oos_res

# Print full unedited JSON transcripts to stdout for tee capture
print(json.dumps(transcripts, indent=2))
with open("artifacts/smoke_test_transcripts.json", "w", encoding="utf-8") as f:
    json.dump(transcripts, f, indent=2)
with open("artifacts/audit_ledger_rows_raw.json", "w", encoding="utf-8") as f:
    json.dump(oos_res.get("audit_ledger_rows", []), f, indent=2)
