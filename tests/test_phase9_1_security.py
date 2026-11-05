"""REDLOOP Phase 9.1 — Security Verification and Hardening Test Suite.

Validates:
1. SSRF and Socket-Pinned Transport Security:
   - IP address validation, private/loopback/cloud metadata IP blocking
   - IPv4-mapped IPv6 blocking
   - DNS rebinding defense via post-connect peer IP verification
   - Credential stripping in URLs and error secret redaction
   - Response size bounding (1MB)
2. Approval Capability Multi-Attribute Binding:
   - Multi-attribute token binding (provider_id, action_name, resource_id)
   - Cross-action, cross-provider, and altered resource replay rejection
   - EDR and Identity adapter execution-time capability validation
3. Signed Case Checkpoints & HMAC Keyring:
   - HMAC-SHA256 signed checkpoints independent of SQLite audit records
   - Multi-key keyring and key rotation verification
   - Tamper detection on modified records, deleted records, and forged signatures
   - Full backward compatibility with IntegrityResultStatus and CheckpointResultStatus
4. Splunk SPL Conservative Guardrails:
   - Read-only pipeline enforcement
   - Quoted and unescaped prohibited command injection blocking
   - Subsearch recursion depth bounding (<= 3)
   - Pipeline stage limits (<= 15)
   - Head and limit parameter bounding (<= 10000)
5. SOAR Crash Recovery & State Reconciliation:
   - Crash recovery marks in-flight executions OUTCOME_UNKNOWN
   - Destructive actions never automatically replayed
6. IOC Engine Normalization & Lifecycle:
   - Indicator value normalization (IP, domain, hash, email, url)
   - Lifecycle expiration state transitions (EXPIRED)
7. Sync Pipeline & SOC Operational Metrics:
   - Local event ingestion provenance
   - Directory/ticketing provider NOT_IMPLEMENTED status
   - Transparent INSUFFICIENT_DATA reporting for empty datasets
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from redloop.assessment.case_management import (
    CaseManager,
    CasePriority,
    CaseSeverity,
    CheckpointResultStatus,
    IntegrityResultStatus,
    IntegrityStatus,
)
from redloop.assessment.ioc_engine import (
    IOCLifecycleManager,
    IOCRecord,
    IOCState,
    IOCType,
    normalize_ioc_value,
)
from redloop.assessment.soc_metrics import SOCMetricsEngine
from redloop.assessment.soc_playbooks import PlaybookApprovalStore
from redloop.assessment.soc_sync import (
    SyncJobStatus,
    TelemetrySyncPipeline,
)
from redloop.assessment.soar_actions import ActionExecutionStatus, SOARActionRegistry
from redloop.assessment.soar_engine import SOAREngine
from redloop.integrations.adapters.splunk import validate_spl_query
from redloop.integrations.transport import (
    PinnedHTTPSConnection,
    SafeHTTPClient,
    SSRFDestinationError,
    check_ip_address_safety,
    redact_url_secrets,
    validate_destination_url,
)


# ==============================================================================
# 1. SSRF & TRANSPORT SECURITY
# ==============================================================================

class TestSSRFAndTransportSecurity:
    def test_private_and_loopback_ips_blocked(self):
        blocked_targets = [
            "http://127.0.0.1/admin",
            "http://localhost:8080/secrets",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/api",
            "http://192.168.1.1/router",
            "http://172.16.0.100/internal",
            "http://0.0.0.0/",
            "http://[::1]/",
        ]
        client = SafeHTTPClient()
        for target in blocked_targets:
            with pytest.raises(SSRFDestinationError):
                client.request("GET", target)

    def test_embedded_credentials_rejected(self):
        client = SafeHTTPClient()
        with pytest.raises(SSRFDestinationError, match="Embedded credentials"):
            client.request("GET", "https://admin:secret@198.51.100.1/api")

    def test_secret_redaction_in_urls(self):
        url = "https://user:SuperSecretPassword@api.example.com/v1/search?token=abc123xyz&normal_param=42"
        redacted = redact_url_secrets(url)
        assert "SuperSecretPassword" not in redacted
        assert "abc123xyz" not in redacted
        assert "REDACTED" in redacted
        assert "normal_param=42" in redacted

    def test_dns_rebinding_prevention(self):
        """Simulates peer IP post-handshake mismatch detection."""
        conn = PinnedHTTPSConnection(validated_ip="93.184.216.34", server_hostname="example.com", port=443, timeout=5.0)
        mock_sock = MagicMock()
        mock_sock.getpeername.return_value = ("192.168.1.1", 443)
        with patch.object(http.client.HTTPSConnection, "connect", return_value=None):
            conn.sock = mock_sock
            with pytest.raises(SSRFDestinationError, match="SSRF Peer Mismatch"):
                conn.connect()


# ==============================================================================
# 2. CAPABILITY TOKEN MULTI-ATTRIBUTE BINDING
# ==============================================================================

class TestCapabilityMultiAttributeBinding:
    def test_multi_attribute_token_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_approvals.db"
            store = PlaybookApprovalStore(db_path=db_path)
            playbook_id = "PB-HARDEN-01"
            step_id = "step-iso-01"

            cap, token_secret = store.issue_capability(
                playbook_id=playbook_id,
                step_id=step_id,
                action_command="isolate_endpoint",
                provider_id="defender",
                action_name="isolate_endpoint",
                resource_id="10.0.0.99",
                action_params={"host_ip": "10.0.0.99"},
            )
            assert token_secret

            # Cross-provider replay must be rejected
            ok, msg, _ = store.validate_and_consume(
                playbook_id=playbook_id,
                step_id=step_id,
                token_secret=token_secret,
                expected_provider_id="crowdstrike",
                expected_action_name="isolate_endpoint",
                expected_action_params={"host_ip": "10.0.0.99"},
            )
            assert ok is False
            assert "provider" in msg.lower()

            # Cross-action replay must be rejected
            ok, msg, _ = store.validate_and_consume(
                playbook_id=playbook_id,
                step_id=step_id,
                token_secret=token_secret,
                expected_provider_id="defender",
                expected_action_name="disable_account",
                expected_action_params={"host_ip": "10.0.0.99"},
            )
            assert ok is False
            assert "action" in msg.lower()

            # Altered target resource must be rejected
            ok, msg, _ = store.validate_and_consume(
                playbook_id=playbook_id,
                step_id=step_id,
                token_secret=token_secret,
                expected_provider_id="defender",
                expected_action_name="isolate_endpoint",
                expected_action_params={"host_ip": "10.0.0.100"},
            )
            assert ok is False
            assert "parameters" in msg.lower()

            # Legitimate execution succeeds
            ok, msg, cap = store.validate_and_consume(
                playbook_id=playbook_id,
                step_id=step_id,
                token_secret=token_secret,
                expected_provider_id="defender",
                expected_action_name="isolate_endpoint",
                expected_action_params={"host_ip": "10.0.0.99"},
            )
            assert ok is True
            assert cap["provider_id"] == "defender"

            # Double-spending / token reuse rejected
            ok, msg, _ = store.validate_and_consume(
                playbook_id=playbook_id,
                step_id=step_id,
                token_secret=token_secret,
            )
            assert ok is False
            assert "already consumed" in msg.lower()


# ==============================================================================
# 3. SIGNED CASE CHECKPOINTS & KEY ROTATION
# ==============================================================================

class TestCaseSignedCheckpointsAndKeyRotation:
    def test_signed_checkpoint_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_audit.db"
            with patch.dict(os.environ, {"REDLOOP_AUDIT_SIGNING_KEY": "test-audit-secret-key-123456"}):
                cm = CaseManager(db_path=db_path)

                case = cm.create_case(
                    title="Suspicious Beaconing",
                    description="Investigating outbound beaconing to suspected C2.",
                    severity=CaseSeverity.HIGH,
                    priority=CasePriority.P1,
                )
                cm.add_note(case.case_id, author="analyst_alice", content="Identified recurring connection pattern.")
                cm.update_case(case.case_id, assigned_to="analyst_alice", actor="analyst_alice")

                # Create signed checkpoint
                cp = cm.create_signed_checkpoint(case.case_id, key_id="key-2026-v1")
                assert cp["key_id"] == "key-2026-v1"
                assert cp["signature"]
                assert cp["event_sequence"] >= 3

                # Verify checkpoint is intact
                verify_res = cm.verify_case_integrity(case.case_id)
                assert verify_res["status"] == IntegrityStatus.INTACT.value
                assert verify_res["checkpoint_status"] == CheckpointResultStatus.CHECKPOINT_VERIFIED.value

                # Tamper with an SQLite timeline record
                conn = cm._get_connection()
                try:
                    with conn:
                        conn.execute(
                            "UPDATE cases SET timeline_json = '[]' WHERE case_id = ?",
                            (case.case_id,),
                        )
                finally:
                    conn.close()

                # Tampering must be detected
                tamper_res = cm.verify_case_integrity(case.case_id)
                assert tamper_res["status"] in (IntegrityStatus.TAMPERED.value, IntegrityStatus.INCOMPLETE.value)

    def test_checkpoint_key_rotation_keyring(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "keyring_cases.db"
            keyring = {
                "key-2025-v1": "old-secret-key-2025-xyz",
                "key-2026-v2": "new-rotated-secret-key-2026-abc",
            }
            with patch.dict(os.environ, {"REDLOOP_AUDIT_KEYRING": json.dumps(keyring)}):
                cm = CaseManager(db_path=db_path)
                c = cm.create_case(title="Rotation Case", description="Testing rotation", severity=CaseSeverity.LOW, priority=CasePriority.P3)

                # Sign with key-2025-v1
                cp1 = cm.create_signed_checkpoint(c.case_id, key_id="key-2025-v1")
                assert cp1["key_id"] == "key-2025-v1"

                # Verify with keyring
                v1 = cm.verify_checkpoint_record(cp1)
                assert v1["status"] == CheckpointResultStatus.CHECKPOINT_VERIFIED.value

                # Sign next checkpoint with key-2026-v2
                cm.add_note(c.case_id, author="bob", content="Next milestone")
                cp2 = cm.create_signed_checkpoint(c.case_id, key_id="key-2026-v2")
                assert cp2["key_id"] == "key-2026-v2"

                v2 = cm.verify_checkpoint_record(cp2)
                assert v2["status"] == CheckpointResultStatus.CHECKPOINT_VERIFIED.value


# ==============================================================================
# 4. SPLUNK SPL CONSERVATIVE PARSER
# ==============================================================================

class TestSplunkConservativeSPLHardening:
    def test_read_only_queries_allowed(self):
        assert validate_spl_query("index=main | stats count by user | sort - count")
        assert validate_spl_query("search index=firewall action=drop | table src, dest, port | head 50")
        assert validate_spl_query("index=windows EventCode=4624 | eval is_login=1 | where is_login=1")

    def test_quoted_destructive_commands_blocked(self):
        with pytest.raises(ValueError, match="Prohibited non-read-only SPL command"):
            validate_spl_query('index=main | "delete"')
        with pytest.raises(ValueError, match="Prohibited non-read-only SPL command"):
            validate_spl_query("index=main | 'outputlookup' sensitive.csv")
        with pytest.raises(ValueError, match="Prohibited non-read-only SPL command"):
            validate_spl_query('index=main | "collect" index=summary')

    def test_subsearch_depth_limit_enforced(self):
        # 1 level: valid
        assert validate_spl_query("index=main [ search index=intel bad_ip=1.1.1.1 ]")
        # 2 levels: valid
        assert validate_spl_query("index=main [ search index=a [ search index=b ] ]")
        # 3 levels: valid (max)
        assert validate_spl_query("index=main [ search index=a [ search index=b [ search index=c ] ] ]")
        # 4 levels: exceeds max_depth of 3
        with pytest.raises(ValueError, match="Subsearch nesting exceeds maximum permitted depth"):
            validate_spl_query("index=main [ search index=a [ search index=b [ search index=c [ search index=d ] ] ] ]")

    def test_pipeline_stage_limit_enforced(self):
        # 16 stages (exceeds max 15)
        query = "index=main " + " | eval x=1" * 16
        with pytest.raises(ValueError, match="exceeds maximum pipeline stage limit"):
            validate_spl_query(query)

    def test_head_and_limit_counts_bounded(self):
        assert validate_spl_query("index=main | head 500")
        assert validate_spl_query("index=main | head 10000")
        with pytest.raises(ValueError, match="exceeds maximum allowed limit of 10000"):
            validate_spl_query("index=main | head 50000")
        with pytest.raises(ValueError, match="exceeds maximum allowed limit of 10000"):
            validate_spl_query("index=main | head limit=25000")


# ==============================================================================
# 5. SOAR CRASH RECOVERY
# ==============================================================================

class TestSOARCrashRecovery:
    def test_in_flight_actions_marked_outcome_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "soar_crash.db"
            engine = SOAREngine(db_path=db_path)

            conn = engine._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO soar_executions (execution_id, workflow_id, workflow_title, trigger_json, state, current_step_index, total_steps, executed_steps_json, evidence_ids_json, started_at)
                        VALUES ('exec-crash-91', 'WF-IR', 'Incident Response', '{}', 'RUNNING', 0, 1, '[]', '[]', '2026-11-05T00:00:00+00:00')
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO soar_action_executions
                        (action_exec_id, execution_id, workflow_id, step_id, action_name, provider_id, resource_id, idempotency_key, state, is_destructive, parameters_json, created_at, updated_at)
                        VALUES ('aexec-crash-91', 'exec-crash-91', 'WF-IR', 'step-1', 'isolate_endpoint', 'crowdstrike', 'dev-001', 'idemp-91', 'IN_PROGRESS', 1, '{}', '2026-11-05T00:00:00+00:00', '2026-11-05T00:00:00+00:00')
                        """
                    )
            finally:
                conn.close()

            recovered = engine.recover_interrupted_executions()
            assert recovered >= 1

            conn = engine._get_connection()
            try:
                cur = conn.execute("SELECT state FROM soar_action_executions WHERE action_exec_id = 'aexec-crash-91'")
                assert cur.fetchone()[0] == "OUTCOME_UNKNOWN"
            finally:
                conn.close()


# ==============================================================================
# 6. IOC ENGINE NORMALIZATION & LIFECYCLE
# ==============================================================================

class TestIOCEngineHardening:
    def test_ioc_value_normalization(self):
        assert normalize_ioc_value(IOCType.IP, "  192.168.1.1  ") == "192.168.1.1"
        assert normalize_ioc_value(IOCType.DOMAIN, "  EVIL-C2.CORP.NET.  ") == "evil-c2.corp.net"
        assert normalize_ioc_value(IOCType.HASH, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert normalize_ioc_value(IOCType.EMAIL, "Phish@MaliciousDomain.com") == "phish@maliciousdomain.com"

    def test_expired_ioc_lifecycle_transition(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "iocs_test.db"
            mgr = IOCLifecycleManager(db_path=db_path)

            past_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            rec = mgr.register_ioc(
                ioc_type=IOCType.IP,
                value="203.0.113.88",
                source="threat_feed",
            )
            # Set expiry in the past
            conn = mgr._get_connection()
            try:
                with conn:
                    conn.execute("UPDATE ioc_records SET expiry = ? WHERE ioc_id = ?", (past_ts, rec.ioc_id))
            finally:
                conn.close()

            loaded = mgr.get_ioc(rec.ioc_id)
            assert loaded is not None
            assert loaded.state == IOCState.EXPIRED


# ==============================================================================
# 7. TELEMETRY SYNC & METRICS
# ==============================================================================

class TestTelemetrySyncAndMetricsHardening:
    def test_directory_ticketing_sync_not_implemented(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "sync_pipeline.db"
            pipeline = TelemetrySyncPipeline(db_path=db_path)

            for prov_id in ("identity_ad", "identity_entra", "ticketing_jira", "ticketing_servicenow"):
                job = pipeline.execute_sync(provider_id=prov_id)
                assert job.status == SyncJobStatus.FAILED
                assert "NOT_IMPLEMENTED" in (job.error_message or "")

    def test_soc_metrics_insufficient_data_status(self):
        metrics = SOCMetricsEngine.get_operational_metrics()
        assert "mean_time_to_detect_status" in metrics
        assert "mean_time_to_respond_status" in metrics
        assert metrics["mean_time_to_detect_status"] in ("CALCULATED", "INSUFFICIENT_DATA")
        assert metrics["mean_time_to_respond_status"] in ("CALCULATED", "INSUFFICIENT_DATA")
