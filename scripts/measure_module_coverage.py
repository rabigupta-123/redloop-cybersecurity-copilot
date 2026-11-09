import subprocess
import sys
import json
from pathlib import Path

checks = [
    # Floor 85%
    {
        "module": "redloop.scope",
        "file_name": "scope.py",
        "floor": 85.0,
        "tests": ["tests/test_scope.py"]
    },
    {
        "module": "redloop.assessment.scope_guard",
        "file_name": "scope_guard.py",
        "floor": 85.0,
        "tests": ["tests/test_scope.py", "tests/test_single_choke_point.py", "tests/test_terminal_scope_ports.py"]
    },
    {
        "module": "redloop.audit",
        "file_name": "audit.py",
        "floor": 85.0,
        "tests": ["tests/test_audit_triggers.py", "tests/test_audit_verify.py", "tests/test_audit_checkpoint.py"]
    },
    {
        "module": "redloop.assessment.audit_checkpoint",
        "file_name": "audit_checkpoint.py",
        "floor": 85.0,
        "tests": ["tests/test_audit_checkpoint.py", "tests/test_audit_runtime_evidence.py"]
    },
    {
        "module": "redloop.assessment.terminal_engine",
        "file_name": "terminal_engine.py",
        "floor": 85.0,
        "tests": ["tests/test_single_choke_point.py", "tests/test_terminal_scope_ports.py"]
    },
    {
        "module": "redloop.assessment.soar_engine",
        "file_name": "soar_engine.py",
        "floor": 85.0,
        "tests": ["tests/test_phase7_soar_engine.py", "tests/test_phase7_soar_actions.py"]
    },
    {
        "module": "redloop.integrations.transport",
        "file_name": "transport.py",
        "floor": 85.0,
        "tests": ["tests/test_phase9_1_security.py"]
    },
    # Floor 60%
    {
        "module": "redloop.assessment.osint_engine",
        "file_name": "osint_engine.py",
        "floor": 60.0,
        "tests": ["tests/test_osint_integrity.py"]
    },
    {
        "module": "redloop.assessment.email_footprint",
        "file_name": "email_footprint.py",
        "floor": 60.0,
        "tests": ["tests/test_email_footprint.py"]
    },
    {
        "module": "redloop.assessment.virustotal",
        "file_name": "virustotal.py",
        "floor": 60.0,
        "tests": ["tests/test_virustotal.py"]
    },
    {
        "module": "redloop.assessment.ai_tool_agent",
        "file_name": "ai_tool_agent.py",
        "floor": 60.0,
        "tests": ["tests/test_ai_tool_agent_hardening.py"]
    },
    {
        "module": "redloop.assessment.orchestrator",
        "file_name": "orchestrator.py",
        "floor": 60.0,
        "tests": ["tests/test_phase3_agent_orchestration.py"]
    },
    {
        "module": "redloop.chat",
        "file_name": "chat.py",
        "floor": 60.0,
        "tests": ["tests/test_chat.py"]
    },
]

results = []
artifacts_dir = Path("artifacts")
artifacts_dir.mkdir(parents=True, exist_ok=True)
json_tmp = artifacts_dir / "cov_tmp.json"

for c in checks:
    mod = c["module"]
    file_name = c["file_name"]
    floor = c["floor"]
    tests = c["tests"]
    
    if json_tmp.exists():
        json_tmp.unlink()

    cmd = [
        sys.executable, "-m", "pytest",
        f"--cov={mod}",
        "--cov-branch",
        f"--cov-report=json:{json_tmp}",
        *tests,
        "-q"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    
    cov_pct = None
    if json_tmp.exists():
        try:
            with open(json_tmp, encoding="utf-8") as f:
                cov_data = json.load(f)
                files = cov_data.get("files", {})
                for fpath, fdata in files.items():
                    if file_name in fpath:
                        cov_pct = round(fdata["summary"]["percent_covered"], 2)
                        break
                if cov_pct is None and "totals" in cov_data:
                    cov_pct = round(cov_data["totals"]["percent_covered"], 2)
        except Exception:
            pass

    if proc.returncode != 0 and cov_pct is None:
        print(f"DEBUG {mod} failed (exit {proc.returncode}): {proc.stderr[:200]}", flush=True)

    status = "UNKNOWN"
    if cov_pct is not None:
        status = "PASS" if cov_pct >= floor else "FAIL"

    res = {
        "module": mod,
        "coverage": cov_pct,
        "floor": floor,
        "status": status,
        "exit_code": proc.returncode,
    }
    results.append(res)
    print(f"[{status}] {mod}: {cov_pct}% (floor: {floor}%)", flush=True)

with open(artifacts_dir / "branch_coverage_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nSummary:", flush=True)
all_pass = all(r["status"] == "PASS" for r in results)
print(f"All floors met: {all_pass}", flush=True)
