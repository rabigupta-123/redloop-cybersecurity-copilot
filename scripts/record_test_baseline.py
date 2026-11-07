"""Run full test suite with coverage and record baseline results."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

def main():
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    junit_xml = artifacts_dir / "junit_baseline.xml"
    coverage_json = artifacts_dir / "baseline_coverage.json"
    baseline_json = artifacts_dir / "baseline.json"

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "--cov=redloop",
        "--cov-branch",
        f"--cov-report=json:{coverage_json}",
        f"--junitxml={junit_xml}",
        "-q",
    ]

    print(f"Running command: {' '.join(cmd)}", flush=True)
    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True)
    runtime = time.time() - t0
    print(f"Pytest finished in {runtime:.2f}s with exit code {res.returncode}", flush=True)

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
            # Root can be <testsuites> or <testsuite>
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

    baseline_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_collected": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "timeouts": timeouts,
        "runtime_seconds": round(runtime, 2),
        "return_code": res.returncode,
        "stdout_tail": res.stdout[-2000:] if res.stdout else "",
        "stderr_tail": res.stderr[-2000:] if res.stderr else "",
    }

    with open(baseline_json, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)

    print(f"Baseline saved to {baseline_json}: {baseline_data}")

if __name__ == "__main__":
    main()

