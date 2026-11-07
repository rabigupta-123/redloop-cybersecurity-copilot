"""Validate JavaScript syntax across repository using node --check."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from redloop.unified_app import UNIFIED_SCRIPT
from redloop.workbench.legacy_workbench import _WORKBENCH_SCRIPT

def main():
    print("Validating JavaScript assets via node --check...")
    js_files = list(Path(".").rglob("*.js"))
    # Filter out scratch, node_modules, or .git
    js_files = [f for f in js_files if "scratch" not in str(f) and "node_modules" not in str(f) and ".git" not in str(f)]

    # Also validate embedded scripts
    with tempfile.TemporaryDirectory() as tmpdir:
        unified_js = Path(tmpdir) / "unified_script.js"
        unified_js.write_text(UNIFIED_SCRIPT, encoding="utf-8")
        js_files.append(unified_js)

        workbench_js = Path(tmpdir) / "workbench_script.js"
        workbench_js.write_text(_WORKBENCH_SCRIPT, encoding="utf-8")
        js_files.append(workbench_js)

        errors = 0
        for f in js_files:
            res = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[FAIL] {f}: {res.stderr.strip()}")
                errors += 1
            else:
                print(f"[PASS] {f.name} syntax valid.")

        if errors > 0:
            print(f"FAILED: {errors} JavaScript files failed syntax validation.")
            sys.exit(1)
        else:
            print(f"SUCCESS: All {len(js_files)} JavaScript scripts passed syntax validation.")

if __name__ == "__main__":
    main()
