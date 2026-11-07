"""Unit tests for S4: Audit ledger append-only DB triggers and anchor command."""
from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest

from redloop.audit import AuditLogger, install_audit_triggers
from redloop.audit_checkpoint import AuditCheckpointStore


def test_audit_triggers_block_update(tmp_path):
    db_file = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_file)
    logger.log("terminal", "test_action", "SUCCESS", details={"key": "val"})

    conn = sqlite3.connect(str(db_file))
    try:
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="append-only: UPDATE forbidden"):
            conn.execute("UPDATE audit_log SET target = 'tampered' WHERE id = 1")
    finally:
        conn.close()


def test_audit_triggers_block_delete(tmp_path):
    db_file = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_file)
    logger.log("terminal", "test_action", "SUCCESS", details={"key": "val"})

    conn = sqlite3.connect(str(db_file))
    try:
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="append-only: DELETE forbidden"):
            conn.execute("DELETE FROM audit_log WHERE id = 1")
    finally:
        conn.close()


def test_audit_insert_succeeds(tmp_path):
    db_file = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_file)
    ev_id = logger.log("terminal", "recon", "SUCCESS", details={"info": "ok"})
    assert ev_id > 0
    res = logger.verify_chain()
    assert res.get("status") in ("INTEGRITY_VERIFIED", "PASS")


def test_audit_anchor_produces_verifiable_checkpoint(tmp_path):
    db_file = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=db_file)
    logger.log("terminal", "recon", "SUCCESS", details={"step": 1})
    logger.log("terminal", "scan", "SUCCESS", details={"step": 2})

    checkpoint_file = tmp_path / "audit_checkpoint.json"
    key_file = tmp_path / "audit_checkpoint.key"
    store = AuditCheckpointStore(
        db_path=db_file,
        checkpoint_path=checkpoint_file,
        key_path=key_file,
    )
    res = store.create(logger)
    cp = res.get("checkpoint", res)
    assert cp["event_count"] == 2
    assert "head_hash" in cp
    assert cp.get("hmac_present") is True

    import json
    raw_saved = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    assert "hmac" in raw_saved
    assert raw_saved["event_count"] == 2

    verification = store.verify(logger)
    assert verification["status"] == "CHECKPOINT_VALID"
