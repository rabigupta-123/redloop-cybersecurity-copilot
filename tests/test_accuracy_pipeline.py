"""Test suite for Phase 5: Accuracy & Confidence Pipeline.

Verifies:
1. Ground-truth fixture loading (>= 100 prompts across all intent categories).
2. Intent routing evaluation pipeline and confusion matrix calculation.
3. Regression gate: routing accuracy >= baseline threshold (0.95).
4. Multi-factor confidence formula: C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X.
5. Strict verification boundary: inferences NEVER marked VERIFIED.
6. Low-confidence review queue persistence, listing, resolving, and summary metrics.
7. Dashboard API endpoint: GET /api/system/low-confidence-queue and POST /resolve.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from redloop.assessment.evaluation import (
    ConfidenceFactors,
    LowConfidenceReviewQueue,
    VerificationState,
    calculate_confidence,
    calculate_f1,
    calculate_fpr,
    calculate_precision,
    calculate_provenance_completeness,
    calculate_recall,
    calculate_routing_accuracy,
    evaluate_intent_routing,
    get_review_queue,
    resolve_verification_state,
)
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.dashboard import create_app
from redloop.scope import ScopeManager, sign_scope


FIXTURES_DIR = Path(__file__).parent / "fixtures"
GROUND_TRUTH_FILE = FIXTURES_DIR / "intent_ground_truth_v1.json"
BASELINE_FILE = FIXTURES_DIR / "intent_baseline.json"


@pytest.fixture
def orch_env(tmp_path):
    from datetime import date, timedelta
    import yaml

    audit_db = str(tmp_path / "audit.sqlite")
    scope_file = tmp_path / "scope.yaml"
    secret = "test-secret-accuracy-redloop-32b!"
    today = date.today()

    scope_data = {
        "version": 1,
        "id": "test-scope-accuracy",
        "authorized_by": "test-suite",
        "signed_at": "2026-10-26T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["scan", "check", "assess", "probe", "tool_ports", "tool_tls", "tool_web"],
                "ports": [80, 443, 8080],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    scope_mgr = ScopeManager(scope_file, secret)
    orch = TaskOrchestrator(scope_manager=scope_mgr, audit_db=audit_db)
    return orch, scope_mgr, audit_db


def test_01_ground_truth_and_baseline_fixtures_exist():
    assert GROUND_TRUTH_FILE.exists(), f"Missing ground truth fixture: {GROUND_TRUTH_FILE}"
    assert BASELINE_FILE.exists(), f"Missing baseline fixture: {BASELINE_FILE}"

    with open(GROUND_TRUTH_FILE, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        bl_data = json.load(f)

    assert len(gt_data) >= 100, f"Expected at least 100 ground truth items, found {len(gt_data)}"
    assert bl_data.get("minimum_routing_accuracy", 0.0) >= 0.90
    for item in gt_data:
        assert "id" in item
        assert "prompt" in item
        assert "expected_intent" in item
        assert "category" in item


def test_02_routing_accuracy_meets_regression_gate(orch_env):
    orch, _, _ = orch_env
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        bl_data = json.load(f)
    min_accuracy = float(bl_data["minimum_routing_accuracy"])

    report = evaluate_intent_routing(GROUND_TRUTH_FILE, orch)

    assert report["total_prompts"] >= 100
    assert report["routing_accuracy"] >= min_accuracy, (
        f"Routing accuracy {report['routing_accuracy']} fell below baseline {min_accuracy}. "
        f"Misclassifications: {report['misclassifications']}"
    )


def test_03_confusion_matrix_and_per_intent_metrics(orch_env):
    orch, _, _ = orch_env
    report = evaluate_intent_routing(GROUND_TRUTH_FILE, orch)

    cm = report["confusion_matrix"]
    per_intent = report["per_intent_metrics"]

    # Confusion matrix row sum must equal total support
    total_in_cm = sum(sum(row.values()) for row in cm.values())
    assert total_in_cm == report["total_prompts"]

    # Verify every evaluated intent has mathematically sound metrics
    for intent_name, metrics in per_intent.items():
        assert 0.0 <= metrics["precision"] <= 1.0
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["f1"] <= 1.0
        assert 0.0 <= metrics["fpr"] <= 1.0
        assert metrics["tp"] + metrics["fn"] == metrics["support"]


def test_04_transparent_confidence_formula():
    # Base calculation with standard weights
    # S=0.8, D=0.9, I=0.5, F=1.0, P=1.0, X=0.8
    # C = 0.25*0.8 + 0.25*0.9 + 0.20*0.5 + 0.10*1.0 + 0.10*1.0 + 0.10*0.8
    # C = 0.20 + 0.225 + 0.10 + 0.10 + 0.10 + 0.08 = 0.805
    factors = ConfidenceFactors(
        source_reliability=0.8,
        direct_observation=0.9,
        independent_corroboration=0.5,
        freshness=1.0,
        parser_validation=1.0,
        cross_source_consistency=0.8,
    )
    conf = calculate_confidence(factors)
    assert conf == 0.805

    # Verification with keyword arguments
    conf_kwargs = calculate_confidence(
        source_reliability=1.0,
        direct_observation=1.0,
        independent_corroboration=1.0,
        freshness=1.0,
        parser_validation=1.0,
        cross_source_consistency=1.0,
    )
    assert conf_kwargs == 1.0

    # Clamping test: out of bound factors clamped
    conf_clamped = calculate_confidence(
        source_reliability=5.0,
        direct_observation=-2.0,
        independent_corroboration=0.5,
        freshness=1.0,
        parser_validation=1.0,
        cross_source_consistency=0.8,
    )
    # S clamped to 1.0, D clamped to 0.0
    # C = 0.25*1.0 + 0.25*0.0 + 0.20*0.5 + 0.10*1.0 + 0.10*1.0 + 0.10*0.8 = 0.25 + 0.10 + 0.10 + 0.10 + 0.08 = 0.63
    assert conf_clamped == 0.63


def test_05_strict_verification_boundary_never_promotes_inference():
    # High confidence inference must NEVER be marked VERIFIED
    state = resolve_verification_state(
        confidence=1.0,
        directly_observed=False,
        is_inference=True,
    )
    assert state == VerificationState.INFERRED
    assert state != VerificationState.VERIFIED

    # Direct observation with confidence >= 0.90 becomes VERIFIED
    state_obs_high = resolve_verification_state(
        confidence=0.95,
        directly_observed=True,
        is_inference=False,
    )
    assert state_obs_high == VerificationState.VERIFIED

    # Direct observation with confidence < 0.90 is OBSERVED
    state_obs_med = resolve_verification_state(
        confidence=0.85,
        directly_observed=True,
        is_inference=False,
    )
    assert state_obs_med == VerificationState.OBSERVED

    # Provider unconfigured fails closed
    state_unconf = resolve_verification_state(
        confidence=0.95,
        directly_observed=True,
        provider_configured=False,
    )
    assert state_unconf == VerificationState.PROVIDER_NOT_CONFIGURED


def test_06_low_confidence_review_queue_operations(tmp_path):
    queue_db = tmp_path / "review_queue.sqlite"
    queue = LowConfidenceReviewQueue(db_path=queue_db)

    # Initially empty
    summary = queue.get_summary()
    assert summary["total_items"] == 0
    assert summary["pending_review"] == 0

    # Add items
    id1 = queue.add(
        item_type="intent",
        prompt_or_summary="random ambiguous prompt xyz",
        classified_as="GENERAL_CHAT",
        confidence=0.42,
        target="127.0.0.1",
        factors={"action": "general_chat"},
    )
    id2 = queue.add(
        item_type="finding",
        prompt_or_summary="unverified passive vulnerability banner",
        classified_as="INFERRED",
        confidence=0.38,
        target="127.0.0.1",
    )

    items = queue.list_items()
    assert len(items) == 2
    assert items[0]["status"] == "PENDING_REVIEW"

    # Resolve first item
    resolved = queue.resolve(id1, status="APPROVED", reviewed_by="sec-op", notes="Confirmed general inquiry")
    assert resolved is True

    # Check updated state
    updated_item1 = queue.get_item(id1)
    assert updated_item1["status"] == "APPROVED"
    assert updated_item1["reviewed_by"] == "sec-op"
    assert "Confirmed" in updated_item1["resolution_notes"]

    summary = queue.get_summary()
    assert summary["total_items"] == 2
    assert summary["pending_review"] == 1
    assert summary["reviewed"] == 1
    assert 0.35 <= summary["average_confidence"] <= 0.45


def test_07_dashboard_low_confidence_queue_endpoints(orch_env, tmp_path):
    _, scope_mgr, audit_db = orch_env
    app = create_app(db_path=audit_db, scope_manager=scope_mgr)
    client = TestClient(app, base_url="http://testserver")

    # Seed an item in review queue
    rq = get_review_queue()
    test_id = rq.add(
        item_type="intent",
        prompt_or_summary="what about this unknown pattern?",
        classified_as="GENERAL_CHAT",
        confidence=0.45,
        target="127.0.0.1",
    )

    # Test GET /api/system/low-confidence-queue
    resp = client.get("/api/system/low-confidence-queue")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "items" in data
    assert any(it["id"] == test_id for it in data["items"])

    # Test POST /api/system/low-confidence-queue/{id}/resolve
    resolve_resp = client.post(
        f"/api/system/low-confidence-queue/{test_id}/resolve",
        json={"status": "APPROVED", "notes": "Verified by test", "reviewed_by": "qa-lead"},
        headers={"Origin": "http://testserver"},
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["success"] is True

    cross_origin = client.post(
        f"/api/system/low-confidence-queue/{test_id}/resolve",
        json={"status": "APPROVED"},
        headers={"Origin": "https://attacker.invalid"},
    )
    assert cross_origin.status_code == 403

    missing_origin = client.post(
        f"/api/system/low-confidence-queue/{test_id}/resolve",
        json={"status": "APPROVED"},
    )
    assert missing_origin.status_code == 403

    invalid_status = client.post(
        f"/api/system/low-confidence-queue/{test_id}/resolve",
        json={"status": "NOT_A_REAL_STATUS"},
        headers={"Origin": "http://testserver"},
    )
    assert invalid_status.status_code == 400

    # Verify resolution in GET response
    resp_after = client.get("/api/system/low-confidence-queue?status=APPROVED")
    assert resp_after.status_code == 200
    items_approved = resp_after.json()["items"]
    assert any(it["id"] == test_id for it in items_approved)
