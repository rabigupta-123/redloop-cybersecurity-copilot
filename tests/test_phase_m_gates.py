"""Phase M Verification Gate Suite (M.1 Scaled Eval, M.2 Drift Monitor, M.3 Live REST/Chat Wiring)."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient

from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from scripts.monitor_osint_signature_drift import evaluate_signature_drift
from scripts.run_phase_m1_scaled_eval import (
    build_email_holdout_m1_n56,
    build_username_holdout_m1_n60,
    evaluate_scaled_email_m1,
    evaluate_scaled_username_m1,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_gate_m1_scaled_email_and_username_eval_n_ge_50() -> None:
    """Verify M.1 scaled evaluation sets have n >= 50 per module, novel platforms, and Wilson CIs."""
    email_items = build_email_holdout_m1_n56()
    username_items = build_username_holdout_m1_n60()

    assert len(email_items) >= 50
    assert len(username_items) >= 50

    email_report = evaluate_scaled_email_m1(email_items)
    username_report = evaluate_scaled_username_m1(username_items)

    assert email_report["total_pairs"] == 56
    assert email_report["novel_platforms_not_in_l1"] >= 8
    assert 0.70 <= email_report["precision"] <= 1.00
    assert 0.70 <= email_report["recall"] < 1.00
    assert 0.70 <= email_report["accuracy"] < 1.00
    assert len(email_report["precision_wilson_95_ci"]) == 2
    assert len(email_report["recall_wilson_95_ci"]) == 2

    assert username_report["total_pairs"] == 60
    assert username_report["novel_platforms_not_in_l2"] >= 40
    assert 0.70 <= username_report["precision"] <= 1.00
    assert 0.70 <= username_report["recall"] < 1.00
    assert 0.70 <= username_report["accuracy"] < 1.00
    assert len(username_report["precision_wilson_95_ci"]) == 2
    assert len(username_report["recall_wilson_95_ci"]) == 2


def test_gate_m2_signature_drift_monitor_passing_and_flagging() -> None:
    """Verify M.2 signature drift monitor passes clean baseline and flags upstream drift."""
    clean_summary = evaluate_signature_drift(include_observed_drift=False)
    assert clean_summary["total_platforms_checked"] == 113
    assert clean_summary["total_probes"] == 452
    assert clean_summary["total_correct"] == 452
    assert clean_summary["overall_accuracy"] == 1.0
    assert clean_summary["drift_alerts_count"] == 0
    assert clean_summary["overall_status"] == "ALL_SIGNATURES_HEALTHY"

    drift_summary = evaluate_signature_drift(include_observed_drift=True)
    assert drift_summary["total_platforms_checked"] == 113
    assert drift_summary["total_probes"] == 452
    assert drift_summary["drift_alerts_count"] == 2
    assert drift_summary["overall_status"] == "DRIFT_DETECTED"
    flagged_ids = {
        f"{d['module']}:{d['platform_id']}" for d in drift_summary["drifted_platforms"]
    }
    assert flagged_ids == {
        "email_footprint:vimeo",
        "username_footprint:patreon",
    }

    workflow_file = REPO_ROOT / ".github" / "workflows" / "osint_signature_drift.yml"
    assert workflow_file.exists()
    wf_text = workflow_file.read_text(encoding="utf-8")
    assert "cron:" in wf_text
    assert "monitor_osint_signature_drift.py" in wf_text


def test_gate_m3_rest_and_chat_entry_points_enforce_person_scope_gate(tmp_path: Path) -> None:
    """Verify live FastAPI REST and Chat routes return 403 SCOPE_REQUIRED and write audit rows."""
    db_path = tmp_path / "m3_test_audit.db"
    app = create_app(
        db_path=str(db_path),
        operator_identifiers=["rabi.operator@redloop.io", "rabi_sec_ops"],
    )
    client = TestClient(app)
    headers = {"Origin": "http://testserver"}

    # 1. Out-of-scope REST OSINT request -> 403 SCOPE_REQUIRED
    rest_resp = client.post(
        "/api/osint/email",
        json={"email": "stranger@unscoped-external.org"},
        headers=headers,
    )
    assert rest_resp.status_code == 403
    rest_json = rest_resp.json()
    assert rest_json["error_code"] == "SCOPE_REQUIRED"
    assert rest_json["entry_point"] == "rest"
    assert rest_json["audit_logged"] is True

    # 2. Out-of-scope Chat OSINT request -> 403 SCOPE_REQUIRED
    chat_resp = client.post(
        "/api/chat/message",
        json={
            "message": "Investigate username @unscoped_target_handle_99",
            "conversation_id": "m3-test-chat",
        },
        headers=headers,
    )
    assert chat_resp.status_code == 403
    chat_json = chat_resp.json()
    assert chat_json["error_code"] == "SCOPE_REQUIRED"
    assert chat_json["entry_point"] == "chat"
    assert chat_json["audit_logged"] is True

    # 3. Verify SQLite audit_log rows and cryptographic chain
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()]
    conn.close()

    assert len(rows) >= 2
    assert any(
        r["target"] == "stranger@unscoped-external.org"
        and r["status"] == "BLOCKED_SCOPE_REQUIRED"
        for r in rows
    )
    assert any(
        "unscoped_target_handle_99" in r["target"]
        and r["status"] == "BLOCKED_SCOPE_REQUIRED"
        for r in rows
    )
    chain_res = AuditLogger(str(db_path)).verify_chain()
    assert chain_res["valid"] is True
    assert chain_res["status"] == "INTEGRITY_VERIFIED"
