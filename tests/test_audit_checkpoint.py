import json
import sqlite3

import pytest

from redloop.audit import AuditLogger
from redloop.audit_checkpoint import (
    AuditCheckpointError,
    AuditCheckpointStore,
    CHECKPOINT_CHAIN_INVALID,
    CHECKPOINT_KEY_MISMATCH,
    CHECKPOINT_KEY_MISSING,
    CHECKPOINT_MISSING,
    CHECKPOINT_ROLLBACK,
    CHECKPOINT_TAMPERED,
    CHECKPOINT_TRUNCATED,
    CHECKPOINT_VALID,
    CHECKPOINT_VALID_UNANCHORED_TAIL,
)


def _ledger(tmp_path, count=3):
    audit = AuditLogger(tmp_path / "audit.sqlite")
    for index in range(count):
        audit.success("127.0.0.1", f"op{index}", "recon")
    return audit, AuditCheckpointStore(tmp_path / "audit.sqlite")


def test_checkpoint_is_external_and_key_is_separate(tmp_path):
    audit, store = _ledger(tmp_path)

    created = store.create(audit)

    assert created["created"] is True
    assert created["status"] == CHECKPOINT_VALID
    assert store.paths.checkpoint.exists()
    assert store.paths.key.exists()
    assert store.paths.key != tmp_path / "audit.sqlite"
    assert store.paths.checkpoint != tmp_path / "audit.sqlite"
    assert store.paths.key.read_bytes() != b""

    verified = store.verify(audit)
    assert verified["status"] == CHECKPOINT_VALID
    assert verified["valid"] is True
    assert verified["external"] is True
    assert verified["database_independent"] is True


def test_checkpoint_refuses_empty_or_invalid_ledger(tmp_path):
    audit = AuditLogger(tmp_path / "audit.sqlite")
    store = AuditCheckpointStore(tmp_path / "audit.sqlite")

    with pytest.raises(AuditCheckpointError):
        store.create(audit)

    assert not store.paths.checkpoint.exists()


def test_checkpoint_detects_truncation(tmp_path):
    audit, store = _ledger(tmp_path, count=5)
    store.create(audit)

    import sqlite3

    conn = sqlite3.connect(tmp_path / "audit.sqlite")
    conn.execute("DELETE FROM audit_log WHERE id = 5")
    conn.commit()
    conn.close()

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_TRUNCATED
    assert result["valid"] is False


def test_checkpoint_reports_valid_unanchored_tail(tmp_path):
    audit, store = _ledger(tmp_path, count=2)
    store.create(audit)
    audit.success("127.0.0.1", "new", "recon")

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_VALID_UNANCHORED_TAIL
    assert result["valid"] is True
    assert result["tail_events"] == 1


def test_checkpoint_detects_checkpoint_file_tampering(tmp_path):
    audit, store = _ledger(tmp_path)
    store.create(audit)
    payload = json.loads(store.paths.checkpoint.read_text(encoding="utf-8"))
    payload["head_hash"] = "0" * 64
    store.paths.checkpoint.write_text(json.dumps(payload), encoding="utf-8")

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_TAMPERED
    assert result["valid"] is False


def test_checkpoint_detects_missing_checkpoint(tmp_path):
    audit, store = _ledger(tmp_path)
    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_MISSING
    assert result["valid"] is False


def test_checkpoint_detects_file_rollback_using_sequence_sidecar(tmp_path):
    audit, store = _ledger(tmp_path, count=2)
    store.create(audit)
    old = store.paths.checkpoint.read_text(encoding="utf-8")

    audit.success("127.0.0.1", "op2", "recon")
    store.create(audit)
    assert store.verify(audit)["status"] == CHECKPOINT_VALID

    store.paths.checkpoint.write_text(old, encoding="utf-8")

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_ROLLBACK
    assert result["valid"] is False


def test_checkpoint_key_rotation_resigns_and_detects_mismatch(tmp_path):
    audit, store = _ledger(tmp_path)
    store.create(audit)
    old_key_id = store.key_id(store.ensure_key())

    rotated = store.rotate_key(audit)
    assert rotated["rotated"] is True
    assert rotated["old_key_id"] == old_key_id
    assert rotated["new_key_id"] != old_key_id
    assert store.verify(audit)["status"] == CHECKPOINT_VALID

    # An unknown key cannot authenticate the checkpoint.
    store._write_key(b"x" * 32)
    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_KEY_MISMATCH
    assert result["valid"] is False


def test_checkpoint_cannot_be_recreated_without_new_events(tmp_path):
    audit, store = _ledger(tmp_path)
    first = store.create(audit)
    second = store.create(audit)
    assert first["created"] is True
    assert second["created"] is False
    assert second["status"] == CHECKPOINT_VALID


def test_missing_key_is_reported_without_creating_a_replacement(tmp_path):
    audit, store = _ledger(tmp_path)
    store.create(audit)
    checkpoint_before = store.paths.checkpoint.read_text(encoding="utf-8")
    store.paths.key.unlink()

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_KEY_MISSING
    assert result["valid"] is False

    with pytest.raises(AuditCheckpointError):
        store.create(audit)
    assert not store.paths.key.exists()
    assert store.paths.checkpoint.read_text(encoding="utf-8") == checkpoint_before


def test_malformed_key_is_tampering(tmp_path):
    audit, store = _ledger(tmp_path)
    store.create(audit)
    store.paths.key.write_text("not-hexadecimal", encoding="utf-8")

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_TAMPERED
    assert result["valid"] is False


def test_malformed_checkpoint_and_sidecar_are_tampering(tmp_path):
    audit, store = _ledger(tmp_path)
    store.create(audit)
    good_checkpoint = store.paths.checkpoint.read_text(encoding="utf-8")

    store.paths.checkpoint.write_text("{not-json", encoding="utf-8")
    assert store.verify(audit)["status"] == CHECKPOINT_TAMPERED

    store.paths.checkpoint.write_text(good_checkpoint, encoding="utf-8")
    store.paths.sequence.write_text("not-a-number", encoding="utf-8")
    assert store.verify(audit)["status"] == CHECKPOINT_TAMPERED


def test_modified_audit_event_invalidates_checkpoint(tmp_path):
    audit, store = _ledger(tmp_path, count=3)
    store.create(audit)
    conn = sqlite3.connect(tmp_path / "audit.sqlite")
    conn.execute("UPDATE audit_log SET action = 'tampered' WHERE id = 2")
    conn.commit()
    conn.close()

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_CHAIN_INVALID
    assert result["valid"] is False


def test_deleted_middle_event_invalidates_checkpoint(tmp_path):
    audit, store = _ledger(tmp_path, count=4)
    store.create(audit)
    conn = sqlite3.connect(tmp_path / "audit.sqlite")
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    conn.commit()
    conn.close()

    result = store.verify(audit)
    assert result["status"] == CHECKPOINT_CHAIN_INVALID
    assert result["valid"] is False
