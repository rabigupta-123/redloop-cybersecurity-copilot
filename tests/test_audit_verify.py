import sqlite3
import pytest
from redloop.audit import AuditLogger, GENESIS_HASH


def test_audit_hash_chain_creation_and_verification(tmp_path):
    db = tmp_path / "audit_chain.db"
    audit = AuditLogger(db)

    # An empty audit log is NOT successful verification.
    res = audit.verify_chain()
    assert res["status"] == "VERIFICATION_INCOMPLETE"
    assert res["valid"] is False
    assert res["verified_events"] == 0
    assert res["total_events"] == 0


    # Add 3 events
    id1 = audit.started("127.0.0.1", "scan", "recon", ports=[80, 443])
    id2 = audit.success("127.0.0.1", "scan", "recon", open_ports=[80])
    id3 = audit.blocked("192.168.1.1", "scan", "recon", reason="out of scope")

    assert id1 == 1 and id2 == 2 and id3 == 3

    # Verification passes
    res = audit.verify_chain()
    assert res["valid"] is True
    assert res["total_events"] == 3
    assert res["first_id"] == 1
    assert res["last_id"] == 3
    assert len(res["head_hash"]) == 64

    # Verify rows in DB have prev_hash and event_hash
    rows = audit.fetch(limit=10)
    assert len(rows) == 3
    # Most recent first in fetch()
    assert rows[2]["prev_hash"] == GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[2]["event_hash"]
    assert rows[0]["prev_hash"] == rows[1]["event_hash"]


def test_audit_detects_tampered_event(tmp_path):
    db = tmp_path / "audit_tamper.db"
    audit = AuditLogger(db)

    audit.started("127.0.0.1", "check", "web")
    audit.success("127.0.0.1", "check", "web", status_code=200)

    # Tamper with row 2
    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER IF EXISTS audit_no_update")
    conn.execute("UPDATE audit_log SET target = 'attacker.com' WHERE id = 2")
    conn.commit()
    conn.close()

    res = audit.verify_chain()
    assert res["valid"] is False
    assert res["broken_at_id"] == 2
    assert "Tampered event detected" in res["error"]


def test_audit_detects_deleted_event(tmp_path):
    db = tmp_path / "audit_deleted.db"
    audit = AuditLogger(db)

    audit.started("127.0.0.1", "probe", "tls")
    audit.success("127.0.0.1", "probe", "tls")
    audit.started("127.0.0.1", "probe", "dns")

    # Delete row 2
    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER IF EXISTS audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    conn.commit()
    conn.close()

    res = audit.verify_chain()
    assert res["valid"] is False
    assert res["broken_at_id"] == 2
    assert "Deleted event detected" in res["error"]

def test_audit_detects_reordered_event(tmp_path):
    db = tmp_path / "audit_reorder.db"
    audit = AuditLogger(db)
    audit.started("127.0.0.1", "probe", "tls")
    audit.success("127.0.0.1", "probe", "tls")
    audit.started("127.0.0.1", "probe", "dns")

    conn = sqlite3.connect(db)
    row1 = conn.execute("SELECT * FROM audit_log WHERE id = 1").fetchone()
    row3 = conn.execute("SELECT * FROM audit_log WHERE id = 3").fetchone()
    conn.execute("DROP TRIGGER IF EXISTS audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id IN (1, 3)")
    conn.execute("INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?,?)", (3,) + row1[1:])
    conn.execute("INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?,?)", (1,) + row3[1:])
    conn.commit()
    conn.close()

    res = audit.verify_chain()
    assert res["status"] in ("CHAIN_GAP_DETECTED", "TAMPER_DETECTED")
    assert res["valid"] is False
    assert res["failure"]["event_id"] is not None


def test_audit_detects_broken_link(tmp_path):
    db = tmp_path / "audit_link.db"
    audit = AuditLogger(db)
    audit.started("127.0.0.1", "probe", "tls")
    audit.success("127.0.0.1", "probe", "tls")

    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER IF EXISTS audit_no_update")
    conn.execute("UPDATE audit_log SET prev_hash = ? WHERE id = 2", ("0" * 64,))
    conn.commit()
    conn.close()

    res = audit.verify_chain()
    assert res["status"] == "TAMPER_DETECTED"
    assert res["failure"]["kind"] == "BROKEN_LINK"
    assert res["failure"]["event_id"] == 2


def test_audit_anchor_detects_truncation_and_reseal(tmp_path):
    db = tmp_path / "audit_anchor.db"
    audit = AuditLogger(db)
    for i in range(5):
        audit.success("127.0.0.1", f"op{i}", "recon")

    sealed = audit.seal_chain()
    assert sealed["sealed"] is True
    assert sealed["event_count"] == 5

    verified = audit.verify_chain(require_anchor=True)
    assert verified["status"] == "INTEGRITY_VERIFIED"
    assert verified["anchor"]["status"] == "MATCH"

    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER IF EXISTS audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id = 5")
    conn.commit()
    conn.close()

    truncated = audit.verify_chain(require_anchor=True)
    assert truncated["status"] == "CHAIN_GAP_DETECTED"
    assert truncated["failure"]["kind"] == "ANCHOR_GAP"
    assert truncated["valid"] is False

    reseal = audit.seal_chain()
    assert reseal["sealed"] is True
    assert audit.verify_chain(require_anchor=True)["status"] == "INTEGRITY_VERIFIED"


def test_audit_verifies_260_event_chain_without_claiming_anchor(tmp_path):
    db = tmp_path / "audit_scale.db"
    audit = AuditLogger(db)
    for index in range(260):
        audit.success("127.0.0.1", f"op-{index}", "recon", observation=index)

    result = audit.verify_chain()
    assert result["status"] == "INTEGRITY_VERIFIED"
    assert result["valid"] is True
    assert result["total_events"] == 260
    assert result["verified_events"] == 260
    assert result["first_id"] == 1
    assert result["last_id"] == 260
    assert result["anchor"]["present"] is False
    assert result["anchor"]["status"] == "MISSING"
    assert result["checks"]["anchor"] is False
    assert result["anchored"] is False
    assert result["verification_state"] == "UNANCHORED"
    assert "truncation cannot be excluded" in result["message"]

    sealed = audit.seal_chain()
    assert sealed["sealed"] is True
    anchored = audit.verify_chain()
    assert anchored["status"] == "INTEGRITY_VERIFIED"
    assert anchored["anchor"]["present"] is True
    assert anchored["anchor"]["status"] == "MATCH"
    assert anchored["anchor"]["event_count"] == 260
    assert anchored["anchored"] is True
    assert anchored["verification_state"] == "ANCHORED"


def test_audit_require_anchor_fails_incomplete(tmp_path):
    db = tmp_path / "audit_noanchor.db"
    audit = AuditLogger(db)
    audit.success("127.0.0.1", "op", "recon")
    res = audit.verify_chain(require_anchor=True)
    assert res["status"] == "VERIFICATION_INCOMPLETE"
    assert res["failure"]["kind"] == "MISSING_ANCHOR"
    assert res["valid"] is False


def test_audit_redaction_keeps_numeric_token_metrics(tmp_path):
    db = tmp_path / "audit_redaction.db"
    audit = AuditLogger(db)
    fake_key = "gsk_123456789012345678901234567890"

    audit.log(
        "127.0.0.1",
        "llm_call",
        "llm",
        "success",
        {
            "token_count": 42,
            "total_tokens": 128,
            "prompt_tokens": 64,
            "completion_tokens": 64,
            "token": fake_key,
            "message": f"used {fake_key}",
        },
    )

    details = audit.fetch(limit=1)[0]["details"]
    assert details["token_count"] == 42
    assert details["total_tokens"] == 128
    assert details["prompt_tokens"] == 64
    assert details["completion_tokens"] == 64
    assert details["token"] == "[REDACTED]"
    assert fake_key not in details["message"]
    assert "[REDACTED]" in details["message"]
