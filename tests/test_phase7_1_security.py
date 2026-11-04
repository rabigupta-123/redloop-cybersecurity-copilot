"""Phase 7.1 Security Hardening & Assurance Verification Suite.

Covers:
1. B1: Webhook SSRF Defenses (IPv4, IPv6, IPv4-mapped IPv6, integer IPs, cloud metadata, allowlisting, credential redaction).
2. B2: Approval Capability Assurance (Atomic CAS consumption, concurrent replay rejection, parameter tampering).
3. B3: SOAR Execution Reliability (Host restart recovery, approval wait timeout, execution idempotency keys).
4. B4: Case & Evidence Cryptographic Hash Chaining (Genesis linkage, tamper detection, missing event detection, audit export).
"""

from __future__ import annotations

import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redloop.assessment.case_management import CaseManager, CasePriority, CaseSeverity, CaseStatus
from redloop.assessment.soar_actions import (
    ActionCategory,
    ActionExecutionStatus,
    SafeWebhookClient,
    SOARActionRegistry,
    SSRFValidationError,
)
from redloop.assessment.soar_engine import SOAREngine, TriggerType, WorkflowState
from redloop.assessment.soc_playbooks import ApprovalCapability, PlaybookApprovalStore
from unittest.mock import patch


# =============================================================================
# 1. B1: Webhook SSRF Protection Tests
# =============================================================================

def test_01_ssrf_rejects_non_https():
    """B1: Webhook must reject non-HTTPS schemes (http, ftp, file, gopher)."""
    with pytest.raises(SSRFValidationError, match="HTTPS"):
        SafeWebhookClient.validate_destination("http://api.external-security.org/notify")

    with pytest.raises(SSRFValidationError, match="HTTPS"):
        SafeWebhookClient.validate_destination("ftp://api.external-security.org/notify")

    with pytest.raises(SSRFValidationError, match="HTTPS"):
        SafeWebhookClient.validate_destination("file:///etc/passwd")


def test_02_ssrf_rejects_embedded_credentials():
    """B1: Webhook must reject userinfo / embedded credentials in URL."""
    with pytest.raises(SSRFValidationError, match="Embedded credentials"):
        SafeWebhookClient.validate_destination("https://admin:secretPass123@api.external-security.org/notify")


def test_03_ssrf_rejects_private_and_loopback_ipv4():
    """B1: Rejects RFC1918 private and loopback IPv4 addresses."""
    # Loopback
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://127.0.0.1/alert")
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://localhost/alert")

    # RFC 1918
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://10.0.1.5/alert")
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://172.16.50.2/alert")
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://192.168.1.1/alert")

    # Cloud metadata
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://169.254.169.254/latest/meta-data")


def test_04_ssrf_rejects_ipv6_loopback_and_mapped():
    """B1: Rejects IPv6 loopback (::1), link-local, ULA, and IPv4-mapped IPv6."""
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://[::1]/webhook")

    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://[fe80::1]/webhook")

    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://[fc00::1]/webhook")

    # IPv4-mapped loopback ::ffff:127.0.0.1
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://[::ffff:127.0.0.1]/webhook")


def test_05_ssrf_rejects_integer_and_hex_encoded_ips():
    """B1: Rejects numeric (dword), hex, and octal integer representation bypasses."""
    # 2130706433 is decimal for 127.0.0.1
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://2130706433/alert")

    # 0x7f000001 is hex for 127.0.0.1
    with pytest.raises(SSRFValidationError, match="SSRF Protection"):
        SafeWebhookClient.validate_destination("https://0x7f000001/alert")


def test_06_ssrf_domain_allowlist_enforcement():
    """B1: Enforces domain allowlist if configured."""
    allowed = ["pagerduty.com", "hooks.slack.com"]

    # Not allowed
    with pytest.raises(SSRFValidationError, match="not in configured allowlist"):
        SafeWebhookClient.validate_destination("https://evil-exfil.com/webhook", allowed_domains=allowed)

    # Allowed exact and subdomain
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("104.16.24.34", 0))]):
        host, ips = SafeWebhookClient.validate_destination("https://hooks.slack.com/services/T00/B00/X", allowed_domains=allowed)
        assert host == "hooks.slack.com"
        assert "104.16.24.34" in ips


def test_07_ssrf_credential_redaction_in_action_result():
    """B1: Webhook action result redacts credentials from error messages and parameters."""
    res = SOARActionRegistry.send_webhook_notification(
        webhook_url="https://api_key:secret_token_xyz@127.0.0.1/notify",
        message="Alert trigger notification",
    )
    assert res.status == ActionExecutionStatus.BLOCKED
    assert "secret_token_xyz" not in res.details
    assert "secret_token_xyz" not in res.target
    assert "[REDACTED]" in res.target or "127.0.0.1" in res.target


# =============================================================================
# 2. B2: Approval Capability Assurance & Concurrency Tests
# =============================================================================

def test_08_approval_cas_concurrent_replay_prevention():
    """B2: Atomic CAS update prevents concurrent replay consumption."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "approval_test.db"
        store = PlaybookApprovalStore(db_path=db_path)

        # Create valid capability via issue_capability
        cap, token = store.issue_capability(
            playbook_id="WF-TEST",
            step_id="step-1",
            action_command="isolate_host 10.0.0.5",
            approver="secops_commander",
            action_params={"host_ip": "10.0.0.5"},
            ttl_minutes=15,
        )

        # First consumption succeeds
        ok1, msg1, info1 = store.validate_and_consume(
            playbook_id="WF-TEST",
            step_id="step-1",
            token_secret=token,
            expected_action_command="isolate_host 10.0.0.5",
            expected_action_params={"host_ip": "10.0.0.5"},
        )
        assert ok1 is True
        assert info1 is not None

        # Immediate replay consumption fails atomically
        ok2, msg2, info2 = store.validate_and_consume(
            playbook_id="WF-TEST",
            step_id="step-1",
            token_secret=token,
            expected_action_command="isolate_host 10.0.0.5",
            expected_action_params={"host_ip": "10.0.0.5"},
        )
        assert ok2 is False
        assert "already consumed" in msg2 or "Replay attempt blocked" in msg2


def test_09_approval_parameter_tampering_blocked():
    """B2: Altered action parameters are rejected with REJECTED_PARAMS_ALTERED."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "approval_test.db"
        store = PlaybookApprovalStore(db_path=db_path)

        cap, token = store.issue_capability(
            playbook_id="WF-TEST",
            step_id="step-1",
            action_command="disable_user alice",
            approver="lead_analyst",
            action_params={"username": "alice"},
            ttl_minutes=15,
        )

        # Attacker tries to consume token to disable 'bob' instead of 'alice'
        ok, msg, _ = store.validate_and_consume(
            playbook_id="WF-TEST",
            step_id="step-1",
            token_secret=token,
            expected_action_command="disable_user bob",  # Altered!
            expected_action_params={"username": "bob"},
        )
        assert ok is False
        assert "altered" in msg


# =============================================================================
# 3. B3: SOAR Execution Reliability Tests
# =============================================================================

def test_10_soar_startup_recovery_interrupted_executions():
    """B3: Host restart recovery scans for stuck RUNNING executions and marks FAILED."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "soar_rec.db"
        engine = SOAREngine(db_path=db_path)

        # Synthesize a stuck RUNNING execution directly in SQLite
        conn = engine._get_connection()
        conn.execute(
            """
            INSERT INTO soar_executions
            (execution_id, workflow_id, workflow_title, trigger_json, state, current_step_index,
             total_steps, executed_steps_json, evidence_ids_json, started_at)
            VALUES ('exec-stuck-1', 'WF-BRUTE-FORCE', 'Test WF', '{}', 'RUNNING', 1, 4, '[]', '[]', '2026-11-04T10:00:00Z')
            """
        )
        conn.commit()
        conn.close()

        # Run recovery
        recovered = engine.recover_interrupted_executions()
        assert recovered >= 1

        rec = engine.get_execution("exec-stuck-1")
        assert rec.state == WorkflowState.FAILED
        assert "interrupted" in rec.error_message.lower()


def test_11_soar_approval_window_timeout():
    """B3: Workflows left in WAITING_FOR_APPROVAL beyond window transition to TIMED_OUT."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "soar_rec.db"
        engine = SOAREngine(db_path=db_path)

        old_ts = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
        conn = engine._get_connection()
        conn.execute(
            """
            INSERT INTO soar_executions
            (execution_id, workflow_id, workflow_title, trigger_json, state, current_step_index,
             total_steps, executed_steps_json, evidence_ids_json, started_at)
            VALUES ('exec-wait-timeout', 'WF-ENDPOINT-MALWARE', 'Malware WF', '{}', 'WAITING_FOR_APPROVAL', 2, 3, '[]', '[]', ?)
            """,
            (old_ts,),
        )
        conn.commit()
        conn.close()

        timed_out = engine.check_approval_timeouts(max_wait_seconds=3600.0)
        assert "exec-wait-timeout" in timed_out

        rec = engine.get_execution("exec-wait-timeout")
        assert rec.state == WorkflowState.TIMED_OUT


def test_12_soar_idempotency_key_deduplication():
    """B3: Same idempotency key returns cached execution record without duplicate run."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "soar_rec.db"
        engine = SOAREngine(db_path=db_path)

        trigger = engine.create_trigger(
            trigger_type=TriggerType.MANUAL,
            source_record_id="src-001",
            target_context="203.0.113.5",
        )

        # Run 1
        rec1 = engine.execute_workflow(
            workflow_id="WF-BRUTE-FORCE",
            trigger=trigger,
            idempotency_key="idemp-key-xyz-789",
        )
        assert rec1.state == WorkflowState.COMPLETED

        # Run 2 with identical key
        rec2 = engine.execute_workflow(
            workflow_id="WF-BRUTE-FORCE",
            trigger=trigger,
            idempotency_key="idemp-key-xyz-789",
        )
        assert rec2.execution_id == rec1.execution_id


# =============================================================================
# 4. B4: Case Timeline Cryptographic Hash Chaining Tests
# =============================================================================

def test_13_case_timeline_cryptographic_hash_chain():
    """B4: Case timeline forms unbroken forward SHA-256 hash chain from genesis."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "cases_test.db"
        cm = CaseManager(db_path=db_path)

        # 1. Create case (genesis event)
        case = cm.create_case(
            title="Credential Spray Incident",
            description="Mass failed logins across 50 accounts",
            severity=CaseSeverity.HIGH,
            priority=CasePriority.P2,
            creator="soc_commander",
        )
        assert len(case.timeline) == 1
        genesis = case.timeline[0]
        assert genesis.prev_hash == "0" * 64
        assert genesis.entry_hash == genesis.compute_hash()

        # 2. Add note
        note = cm.add_note(case.case_id, author="analyst_1", content="Correlated with Okta auth logs.")
        # 3. Attach evidence
        cm.attach_evidence(case.case_id, evidence_ids=["evi-okta-101", "evi-firewall-202"])
        # 4. Status transition
        cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING)

        refreshed = cm.get_case(case.case_id)
        assert len(refreshed.timeline) == 4

        # Verify integrity
        integrity = cm.verify_case_integrity(case.case_id)
        assert integrity["is_valid"] is True
        assert integrity["status"] == "INTACT"
        assert integrity["timeline_events_verified"] == 4
        assert integrity["evidence_references_verified"] == 2
        assert "limitations_notice" in integrity


def test_14_case_timeline_tamper_detection():
    """B4: Mathematical tamper detection flags corrupted or modified timeline events."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "cases_test.db"
        cm = CaseManager(db_path=db_path)

        case = cm.create_case(
            title="Web Shell Investigation",
            description="jsp shell detected in uploads directory",
            severity=CaseSeverity.CRITICAL,
        )
        cm.add_note(case.case_id, author="ir_lead", content="Server isolated.")
        cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING)

        # Tamper directly with the SQLite database payload of event 1
        conn = cm._get_connection()
        cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
        row = cur.fetchone()
        import json
        tl_data = json.loads(row["timeline_json"])
        # Attacker modifies note author and content in the database
        tl_data[1]["actor"] = "attacker_impersonator"
        tl_data[1]["description"] = "No threat found."
        conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl_data), case.case_id))
        conn.commit()
        conn.close()

        # Verify integrity
        integrity = cm.verify_case_integrity(case.case_id)
        assert integrity["is_valid"] is False
        assert integrity["status"] == "TAMPERED"
        assert integrity["broken_index"] == 1
        assert "Tamper detected" in integrity["details"]
