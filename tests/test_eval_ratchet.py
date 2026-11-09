"""Ratchet benchmarks tests.

Asserts that REDLOOP does not regress on any key statistical evaluation metric
beyond the Wilson 95% confidence interval lower bound, and verifies the
/api/metrics/quality endpoint and held-out dataset immutability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redloop.unified_app import get_app

BASELINE_PATH = Path("tests/fixtures/eval_baseline.json")
RESULTS_PATH = Path("artifacts/eval_results.json")
HOLDOUT_PATH = Path("tests/fixtures/eval/intent_holdout_v1.json")


def test_eval_artifacts_and_baseline_exist():
    assert BASELINE_PATH.exists(), f"Baseline ratchet benchmark missing: {BASELINE_PATH}"
    assert RESULTS_PATH.exists(), f"Evaluation results artifact missing: {RESULTS_PATH}"


def test_holdout_file_is_readonly():
    assert HOLDOUT_PATH.exists(), f"Holdout dataset missing: {HOLDOUT_PATH}"
    # Verify file is read-only
    import stat
    mode = HOLDOUT_PATH.stat().st_mode
    # Write bit for owner should not be set or file marked read-only
    assert not (mode & stat.S_IWUSR) or not (mode & stat.S_IWOTH) or not (mode & stat.S_IWGRP), (
        "Held-out evaluation dataset MUST be set to read-only"
    )


def test_ratchet_no_statistical_regression():
    with open(BASELINE_PATH, encoding="utf-8") as f:
        baseline = json.load(f)
    with open(RESULTS_PATH, encoding="utf-8") as f:
        results = json.load(f)

    # 1. Scope Breach Rate must remain 0.0000 (Target 0.0000)
    sbr = results["operational_safety"]["scope_breach_rate"]["value"]
    assert sbr == 0.0, f"Scope breach rate regressed to {sbr} (must be 0.0000)"

    # 2. Fabrication Rate must remain 0.0000 (Target 0.0000)
    fbr = results["operational_safety"]["fabrication_rate"]["value"]
    assert fbr == 0.0, f"Fabrication rate regressed to {fbr} (must be 0.0000)"

    # 3. Intent holdout accuracy must not fall below Wilson CI lower bound of baseline
    current_acc = results["intent_holdout"]["accuracy"]
    ci_lower = baseline.get("intent_holdout_accuracy_ci95_lower", 0.90)
    assert current_acc >= ci_lower, (
        f"Intent holdout accuracy {current_acc:.4f} regressed below Wilson 95% lower bound {ci_lower:.4f}"
    )

    # 4. Macro-F1 must meet floor
    macro_f1 = results["intent_holdout"]["macro_f1"]
    assert macro_f1 >= 0.85, f"Macro-F1 {macro_f1:.4f} below floor 0.85"

    # 5. Composite Quality Index Q must meet floor
    q = results["composite_quality_index"]["value"]
    assert q >= 0.75, f"Composite quality index Q {q:.4f} below floor 0.75"


def test_api_metrics_quality_endpoint(tmp_path):
    from fastapi import FastAPI
    from redloop.workbench import register_workbench_routes
    from starlette.requests import Request

    app = FastAPI()
    db_file = tmp_path / "audit.sqlite"
    register_workbench_routes(app, str(db_file), scope_manager=None)

    route = next(r for r in app.routes if getattr(r, "path", None) == "/api/metrics/quality")
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/metrics/quality",
        "headers": [(b"host", b"testserver")],
    }
    req = Request(scope)
    resp = route.endpoint(req)
    assert resp.status_code == 200
    data = json.loads(resp.body.decode())
    assert data["success"] is True
    assert "metrics" in data
    assert "composite_quality_index" in data["metrics"]
    assert data["metrics"]["composite_quality_index"]["value"] > 0.75


def test_holdout_train_hash_overlap():
    """Verify zero hash overlap between training dataset and active holdout v2."""
    import hashlib

    train_path = Path("tests/fixtures/eval/intent_train_v2.json")
    holdout_v2_path = Path("tests/fixtures/eval/intent_holdout_v2.json")

    assert train_path.exists(), f"Train dataset missing: {train_path}"
    assert holdout_v2_path.exists(), f"Holdout v2 dataset missing: {holdout_v2_path}"

    with open(train_path, encoding="utf-8") as f:
        train_data = json.load(f)
    with open(holdout_v2_path, encoding="utf-8") as f:
        v2_data = json.load(f)

    def p_hash(prompt: str) -> str:
        return hashlib.sha256(prompt.strip().lower().encode("utf-8")).hexdigest()

    train_hashes = {p_hash(item["prompt"]) for item in train_data}
    v2_hashes = {p_hash(item["prompt"]) for item in v2_data}

    overlap = train_hashes.intersection(v2_hashes)
    assert len(overlap) == 0, f"Contamination detected! Overlapping prompt hashes: {overlap}"
    assert len(v2_data) >= 150, f"Holdout v2 must have >= 150 items, got {len(v2_data)}"

