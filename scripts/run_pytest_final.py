"""Run pytest final verification with real-time logging and record artifacts/final.json and final_coverage.json."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

def main():
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    junit_xml = artifacts_dir / "junit_final.xml"
    coverage_json = artifacts_dir / "final_coverage.json"
    final_json = artifacts_dir / "final.json"
    log_file = artifacts_dir / "pytest_final.log"

    cmd = [
        sys.executable,
        "-u",
        "-m",
        "pytest",
        "--cov=redloop",
        "--cov-branch",
        f"--cov-report=json:{coverage_json}",
        f"--junitxml={junit_xml}",
        "--tb=short",
        "-v",
    ]

    print(f"Starting pytest final verification: {' '.join(cmd)}", flush=True)
    t0 = time.time()
    
    with open(log_file, "w", encoding="utf-8", buffering=1) as out_f:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        for line in proc.stdout:
            out_f.write(line)
            if "FAILED" in line or "PASSED" in line or "SKIPPED" in line or "ERROR" in line or "Timeout" in line or "passed" in line:
                print(line.strip(), flush=True)
        proc.wait()
    
    runtime = time.time() - t0
    ret = proc.returncode
    print(f"Pytest finished in {runtime:.2f}s with return code {ret}", flush=True)

    passed = 0
    failed = 0
    skipped = 0
    errors = 0
    timeouts = 0
    total = 0

    if junit_xml.exists():
        try:
            tree = ET.parse(junit_xml)
            root = tree.getroot()
            suites = root.findall(".//testsuite") if root.tag == "testsuites" else [root]
            for s in suites:
                total += int(s.attrib.get("tests", 0))
                failed += int(s.attrib.get("failures", 0))
                errors += int(s.attrib.get("errors", 0))
                skipped += int(s.attrib.get("skipped", 0))

            for tc in root.findall(".//testcase"):
                fail = tc.find("failure")
                err = tc.find("error")
                content = ""
                if fail is not None and fail.text:
                    content += fail.text
                if err is not None and err.text:
                    content += err.text
                if "Timeout >" in content or "timed out after" in content:
                    timeouts += 1

            passed = total - failed - errors - skipped
        except Exception as e:
            print(f"Error parsing junit xml: {e}", flush=True)

    final_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_collected": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "timeouts": timeouts,
        "runtime_seconds": round(runtime, 2),
        "return_code": ret,
    }

    with open(final_json, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=2)

    print("Final results saved to artifacts/final.json:")
    print(json.dumps(final_data, indent=2), flush=True)

if __name__ == "__main__":
    main()
