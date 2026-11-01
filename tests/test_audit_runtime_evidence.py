"""Source-of-truth and UI-contract evidence for audit verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from redloop.audit import (
    AuditLogger,
    compute_canonical_event_json,
    compute_event_hash,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DB = REPO_ROOT / "data" / "audit.db"


@pytest.mark.skipif(not PROJECT_DB.exists(), reason="project audit database is not present")
def test_project_audit_db_all_events_recomputed_independently():
    audit = AuditLogger(PROJECT_DB)
    res = audit.verify_chain()

    assert res["status"] == "INTEGRITY_VERIFIED"
    assert res["valid"] is True
    assert res["total_events"] == 259
    assert res["verified_events"] == 259

    conn = __import__("sqlite3").connect(PROJECT_DB)
    try:
        rows = conn.execute(
            "SELECT id, timestamp, target, action, module, status, details, scope_entry, prev_hash, event_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    expected_prev = "0" * 64
    for row_id, ts, target, action, module, status, details, scope_entry, prev_hash, event_hash in rows:
        assert prev_hash == expected_prev, f"broken prev_hash at id {row_id}"
        canonical = compute_canonical_event_json(
            ts, target, action, module, status, details, scope_entry
        )
        assert compute_event_hash(canonical, prev_hash) == event_hash, f"hash mismatch at id {row_id}"
        expected_prev = event_hash
    assert len(rows) == 259


def test_ui_never_reports_tamper_for_a_valid_chain(tmp_path):
    from fastapi.testclient import TestClient
    from redloop.dashboard import create_app

    db = tmp_path / "audit.db"
    audit = AuditLogger(db)
    for i in range(3):
        audit.success("127.0.0.1", f"op{i}", "recon")

    client = TestClient(create_app(str(db)))

    payload = client.get("/api/audit/verify").json()
    assert payload["status"] == "INTEGRITY_VERIFIED"
    assert payload["valid"] is True
    assert payload["verified_events"] == 3

    for route in ("/", "/workbench"):
        html = client.get(route).text
        assert "INTEGRITY_VERIFIED" in html
        assert "CHAIN_GAP_DETECTED" in html
        assert "data.chain_valid" not in html
        assert "TAMPER DETECTED: ${data.message}" not in html

    audit_row = audit.fetch(limit=1)[0]
    conn = __import__("sqlite3").connect(db)
    conn.execute("UPDATE audit_log SET target = 'attacker.example' WHERE id = ?", (audit_row["id"],))
    conn.commit()
    conn.close()

    tampered = client.get("/api/audit/verify").json()
    assert tampered["status"] == "TAMPER_DETECTED"
    assert tampered["valid"] is False
    assert tampered["failure"]["event_id"] == audit_row["id"]
    assert "Tampered event detected" in tampered["error"]


def test_empty_audit_is_verification_incomplete_over_http(tmp_path):
    from fastapi.testclient import TestClient
    from redloop.dashboard import create_app

    client = TestClient(create_app(str(tmp_path / "empty.db")))
    payload = client.get("/api/audit/verify").json()
    assert payload["status"] == "VERIFICATION_INCOMPLETE"
    assert payload["valid"] is False
    assert payload["message"]
    assert payload["verification_state"] == "EMPTY_LOG"
    assert payload["failure"]["kind"] == "EMPTY_LOG"
    assert payload["anchor"]["status"] == "MISSING"
    assert payload["anchor"]["present"] is False
