"""Branch Coverage Ratchet Verification (Phase 1.4).

Verifies per-module branch coverage floors:
Floor 85%:
- src/redloop/scope.py
- src/redloop/assessment/scope_guard.py
- src/redloop/audit.py
- src/redloop/assessment/audit_checkpoint.py
- src/redloop/assessment/terminal_engine.py
- src/redloop/assessment/soar_engine.py
- src/redloop/integrations/transport.py

Floor 60%:
- src/redloop/assessment/osint_engine.py
- src/redloop/assessment/email_footprint.py
- src/redloop/assessment/virustotal.py
- src/redloop/assessment/ai_tool_agent.py
- src/redloop/assessment/orchestrator.py
- src/redloop/chat.py
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest


def test_branch_coverage_ratchet():
    results_path = Path("artifacts/branch_coverage_results.json")
    assert results_path.exists(), f"Coverage benchmark artifact {results_path} not found. Run measure_module_coverage.py first."

    with open(results_path, encoding="utf-8") as f:
        records = json.load(f)

    assert len(records) >= 13, f"Expected 13 module coverage records, got {len(records)}"

    failures = []
    for r in records:
        mod = r["module"]
        cov = r.get("coverage")
        floor = r.get("floor", 0.0)

        assert cov is not None, f"Coverage not computed for module {mod}"
        if cov < floor:
            failures.append(f"{mod}: {cov}% < floor {floor}%")

    assert not failures, f"Coverage ratchet floors violated:\n" + "\n".join(failures)

