"""Snapshot baseline intent metrics."""
from __future__ import annotations

import json
from pathlib import Path
from datetime import date, timedelta
import yaml

from redloop.assessment.evaluation import evaluate_intent_routing
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.scope import ScopeManager, sign_scope

def main():
    fixtures_dir = Path("tests/fixtures")
    gt_file = fixtures_dir / "intent_ground_truth_v1.json"
    
    # Setup standard temporary in-memory orchestrator
    today = date.today()
    scope_data = {
        "version": 1,
        "id": "baseline-scope",
        "authorized_by": "baseline",
        "signed_at": "2026-10-26T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["*"],
            }
        ],
    }
    secret = "baseline-intent-secret-key-32b!"
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file = Path("artifacts/tmp_scope.yaml")
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    
    scope_mgr = ScopeManager(scope_file, secret)
    orch = TaskOrchestrator(scope_manager=scope_mgr, audit_db=":memory:")
    
    report = evaluate_intent_routing(gt_file, orch)
    
    out_file = Path("artifacts/intent_baseline_metrics.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    
    if scope_file.exists():
        scope_file.unlink()
        
    print(f"Intent metrics saved to {out_file}: accuracy={report['routing_accuracy']:.4f}, prompts={report['total_prompts']}")

if __name__ == "__main__":
    main()

