"""Phase 5.2 Security Assurance & Reliability Hardening Verification Suite.

Verifies:
1. Cryptographic Capability Issuance (B1): High-entropy secrets, SHA-256 hash storage.
2. Prefix-Spoofing Rejection (B1): String prefixes like rl-auth-* or rl-cap-* cannot bypass authorization.
3. Authorized Capability Execution & Consumption (B1): Valid token executes containment and marks consumed.
4. Replay Attack Prevention (B1): Re-using the same capability token fails atomically.
5. Binding Mismatch Prevention (B1): Token bound to Playbook A Step 1 cannot execute Step 2.
6. Prerequisite Approval Enforcement (B1): Unapproved steps cannot be executed under any token.
7. Expiration (TTL) Enforcement (B1): Tokens past their 15-minute validity window are rejected.
8. Concurrent Execution Safety (B1): Thread-safe atomic consumption prevents race-condition double execution.
9. SQLite Persistence Across Restarts (B1/B5): Capabilities and audit log survive process restarts.
10. Bounded Double-URL Decoding (B2): Detects %252e%252e%252f traversal and %2520UNION%2520SELECT SQLi.
11. Negative False-Positive Tests (B2): Benign paths (/assets/fonts/union.woff, /css/select2.min.css) do not alert.
12. Formula Compliance & NaN/Inf Boundaries (B3): Heuristic labeling, strict EPSS [0, 1] bounds, NaN rejection.
13. Full Audit Trail Verification (B1): Every approval, execution, rejection, and replay is logged to audit database.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
import math
import sqlite3
import pytest

from redloop.assessment.analytics import EvidenceConfidenceCalculator
from redloop.assessment.intel_engine import VulnerabilityIntelligenceEngine
from redloop.assessment.soc_detection import SOCAlert, SOCDetectionEngine
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_playbooks import (
    ApprovalCapability,
    PlaybookApprovalStore,
    PlaybookStepStatus,
    SOCPlaybookEngine,
)


@pytest.fixture(autouse=True)
def clean_playbooks_and_store(tmp_path):
    """Ensures each test operates on an isolated SQLite database and fresh playbooks."""
    db_file = tmp_path / "test_audit.db"
    store = PlaybookApprovalStore(db_path=db_file)
    PlaybookApprovalStore._instance = store
    SOCPlaybookEngine._reset_playbooks()
    yield
    store.reset()
    SOCPlaybookEngine._reset_playbooks()


# =========================================================================
# Part 1: Cryptographic Capability Token & Approval Security (B1)
# =========================================================================

def test_01_cryptographic_capability_issuance():
    """Approving a containment step issues a cryptographic capability token with SHA-256 hash storage."""
    res_app = SOCPlaybookEngine.approve_step(
        "PB-CRED", "step-cred-2", approver="lead_analyst_alice", approved=True
    )
    assert res_app["success"] is True
    assert res_app["status"] == PlaybookStepStatus.APPROVED.value
    assert "capability_token" in res_app
    assert "capability_id" in res_app
    assert "expires_at" in res_app

    cap_token = res_app["capability_token"]
    assert cap_token.startswith("rl-cap-")
    assert len(cap_token) >= 40  # High-entropy token

    # Verify database holds only SHA-256 hash, never plaintext secret
    store = PlaybookApprovalStore.get_instance()
    conn = store._get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM playbook_approval_capabilities WHERE capability_id = ?",
            (res_app["capability_id"],),
        ).fetchone()
        assert row is not None
        assert row["token_hash"] == hashlib.sha256(cap_token.encode("utf-8")).hexdigest()
        assert row["token_hash"] != cap_token
        assert row["consumed"] == 0
        assert row["playbook_id"] == "PB-CRED"
        assert row["step_id"] == "step-cred-2"
    finally:
        conn.close()


def test_02_prefix_spoofing_rejected():
    """Arbitrary prefix strings such as 'rl-auth-fake' or 'rl-cap-fake' cannot execute steps."""
    # Step requires approval
    pb = SOCPlaybookEngine.get_playbook("PB-CRED")
    step = pb.steps[1]
    assert step.requires_approval is True

    # Approve to transition state to APPROVED
    SOCPlaybookEngine.approve_step("PB-CRED", step.step_id, approver="lead", approved=True)

    # Attacker tries arbitrary tokens matching old or new prefix
    for bad_token in ["rl-auth-attacker", "rl-auth-admin-token", "rl-cap-forged-random-token", "invalid-token"]:
        res_exec = SOCPlaybookEngine.execute_step("PB-CRED", step.step_id, auth_token=bad_token)
        assert res_exec["success"] is False
        assert "Execution rejected" in res_exec["error"]

    # Step must still be APPROVED and unexecuted
    assert step.approval_status == PlaybookStepStatus.APPROVED


def test_03_valid_capability_execution_and_consumption():
    """Executing an approved step with the genuine capability token succeeds and transitions status."""
    res_app = SOCPlaybookEngine.approve_step("PB-CRED", "step-cred-2", approver="security_officer", approved=True)
    cap_token = res_app["capability_token"]

    res_exec = SOCPlaybookEngine.execute_step("PB-CRED", "step-cred-2", auth_token=cap_token, operator="operator_dan")
    assert res_exec["success"] is True
    assert res_exec["status"] == PlaybookStepStatus.EXECUTED.value
    assert "successfully executed" in res_exec["execution_result"]

    # Confirm database marked as consumed
    store = PlaybookApprovalStore.get_instance()
    conn = store._get_connection()
    try:
        row = conn.execute(
            "SELECT consumed, consumed_at FROM playbook_approval_capabilities WHERE capability_id = ?",
            (res_app["capability_id"],),
        ).fetchone()
        assert row["consumed"] == 1
        assert row["consumed_at"] is not None
    finally:
        conn.close()


def test_04_replay_attack_prevention():
    """Replaying an already-consumed capability token is strictly blocked."""
    res_app = SOCPlaybookEngine.approve_step("PB-BRUTE", "step-brute-2", approver="lead_carl", approved=True)
    cap_token = res_app["capability_token"]

    # First execution succeeds
    res_exec1 = SOCPlaybookEngine.execute_step("PB-BRUTE", "step-brute-2", auth_token=cap_token)
    assert res_exec1["success"] is True

    # Replay attempt fails
    res_exec2 = SOCPlaybookEngine.execute_step("PB-BRUTE", "step-brute-2", auth_token=cap_token)
    assert res_exec2["success"] is False
    assert "already consumed" in res_exec2["error"] or "Replay attempt blocked" in res_exec2["error"]


def test_05_binding_mismatch_prevention():
    """A capability token bound to Playbook A Step 1 cannot execute Playbook B or Step 2."""
    res_app = SOCPlaybookEngine.approve_step("PB-BRUTE", "step-brute-2", approver="lead", approved=True)
    token_brute = res_app["capability_token"]

    # Also approve step in PB-CRED
    SOCPlaybookEngine.approve_step("PB-CRED", "step-cred-2", approver="lead", approved=True)

    # Attempt cross-playbook execution
    res_cross = SOCPlaybookEngine.execute_step("PB-CRED", "step-cred-2", auth_token=token_brute)
    assert res_cross["success"] is False
    assert "bound to playbook" in res_cross["error"]


def test_06_unapproved_step_execution_rejected():
    """Unapproved containment step cannot be executed even if an attacker generates a random token."""
    pb = SOCPlaybookEngine.get_playbook("PB-PSHELL")
    step = pb.steps[1]
    assert step.approval_status == PlaybookStepStatus.PENDING

    res_exec = SOCPlaybookEngine.execute_step("PB-PSHELL", step.step_id, auth_token="rl-cap-unapproved")
    assert res_exec["success"] is False
    assert "requires explicit human approval" in res_exec["error"]


def test_07_capability_expiration_ttl():
    """Capability tokens past their 15-minute TTL are rejected."""
    store = PlaybookApprovalStore.get_instance()
    now = datetime.now(timezone.utc)
    expired_time = (now - timedelta(minutes=20)).isoformat()
    
    # Manually insert expired capability
    secret = "rl-cap-test-expired-token-secret-123456"
    thash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    conn = store._get_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO playbook_approval_capabilities
                (capability_id, token_hash, playbook_id, step_id, action_command, approver, created_at, expires_at, consumed, nonce)
                VALUES ('cap-expired-1', ?, 'PB-WEB', 'step-web-2', 'block ip', 'lead', ?, ?, 0, 'nonce1')
                """,
                (thash, (now - timedelta(minutes=35)).isoformat(), expired_time),
            )
    finally:
        conn.close()

    # Pre-approve step in memory
    pb = SOCPlaybookEngine.get_playbook("PB-WEB")
    for s in pb.steps:
        if s.step_id == "step-web-2":
            s.approval_status = PlaybookStepStatus.APPROVED

    res = SOCPlaybookEngine.execute_step("PB-WEB", "step-web-2", auth_token=secret)
    assert res["success"] is False
    assert "expired" in res["error"].lower()


def test_08_concurrent_execution_race_condition():
    """Under concurrent execution race conditions, exactly one consumer succeeds."""
    res_app = SOCPlaybookEngine.approve_step("PB-MALWARE", "step-mal-2", approver="lead_frank", approved=True)
    cap_token = res_app["capability_token"]

    results = []
    def try_execute(worker_id: int):
        return SOCPlaybookEngine.execute_step(
            "PB-MALWARE", "step-mal-2", auth_token=cap_token, operator=f"worker_{worker_id}"
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(try_execute, i) for i in range(8)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    success_count = sum(1 for r in results if r["success"] is True)
    failure_count = sum(1 for r in results if r["success"] is False)
    assert success_count == 1
    assert failure_count == 7


def test_09_persistence_across_restarts(tmp_path):
    """Capabilities stored in SQLite persist and can be validated by a newly initialized engine."""
    db_file = tmp_path / "persistent_audit.db"
    store1 = PlaybookApprovalStore(db_path=db_file)
    PlaybookApprovalStore._instance = store1
    SOCPlaybookEngine._reset_playbooks()

    res_app = SOCPlaybookEngine.approve_step("PB-EXFIL", "step-ex-2", approver="ciso", approved=True)
    token = res_app["capability_token"]

    # Simulate restart: create new store pointing to same database
    PlaybookApprovalStore._instance = None
    store2 = PlaybookApprovalStore(db_path=db_file)
    PlaybookApprovalStore._instance = store2

    # In a fresh memory catalog, set the step to approved as would be reloaded
    pb = SOCPlaybookEngine.get_playbook("PB-EXFIL")
    for s in pb.steps:
        if s.step_id == "step-ex-2":
            s.approval_status = PlaybookStepStatus.APPROVED

    res_exec = SOCPlaybookEngine.execute_step("PB-EXFIL", "step-ex-2", auth_token=token)
    assert res_exec["success"] is True
    assert res_exec["status"] == PlaybookStepStatus.EXECUTED.value


# =========================================================================
# Part 2: Detection Engine Bounded URL Decoding & False Positives (B2)
# =========================================================================

def test_10_bounded_double_url_decoding():
    """Detects double-encoded directory traversal and SQL injection payloads safely."""
    engine = SOCDetectionEngine()

    # Double-encoded traversal: %252e%252e%252f -> %2e%2e%2f -> ../
    double_trav_event = UniversalSecurityEvent(
        event_id="evt-dtrav-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="web_access",
        source_file="access.log",
        event_category=EventCategory.WEB,
        event_action="http_request",
        severity=EventSeverity.HIGH,
        url="/view?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        raw_data="GET /view?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1",
    )
    alerts = engine.run_detections([double_trav_event])
    assert any("Traversal" in a.title for a in alerts)

    # Double-encoded SQLi: %2520 -> %20 -> space
    double_sqli_event = UniversalSecurityEvent(
        event_id="evt-dsqli-1",
        timestamp="2026-11-04T12:00:05Z",
        ingestion_timestamp="2026-11-04T12:00:06Z",
        source_type="web_access",
        source_file="access.log",
        event_category=EventCategory.WEB,
        event_action="http_request",
        severity=EventSeverity.HIGH,
        url="/products?cat=1%2520UNION%2520SELECT%2520username,password%2520FROM%2520users",
        raw_data="GET /products?cat=1%2520UNION%2520SELECT%2520username,password%2520FROM%2520users HTTP/1.1",
    )
    alerts_sqli = engine.run_detections([double_sqli_event])
    assert any("SQL Injection" in a.title for a in alerts_sqli)


def test_11_negative_tests_benign_urls():
    """Benign web assets containing 'select' or 'union' do not produce false positive alerts."""
    engine = SOCDetectionEngine()

    benign_events = [
        UniversalSecurityEvent(
            event_id="b1",
            timestamp="2026-11-04T12:01:00Z",
            ingestion_timestamp="2026-11-04T12:01:01Z",
            source_type="web_access",
            source_file="access.log",
            event_category=EventCategory.WEB,
            event_action="http_request",
            severity=EventSeverity.INFORMATIONAL,
            url="/assets/fonts/union.woff",
            raw_data="GET /assets/fonts/union.woff HTTP/1.1",
        ),
        UniversalSecurityEvent(
            event_id="b2",
            timestamp="2026-11-04T12:01:02Z",
            ingestion_timestamp="2026-11-04T12:01:03Z",
            source_type="web_access",
            source_file="access.log",
            event_category=EventCategory.WEB,
            event_action="http_request",
            severity=EventSeverity.INFORMATIONAL,
            url="/css/select2.min.css",
            raw_data="GET /css/select2.min.css HTTP/1.1",
        ),
        UniversalSecurityEvent(
            event_id="b3",
            timestamp="2026-11-04T12:01:04Z",
            ingestion_timestamp="2026-11-04T12:01:05Z",
            source_type="web_access",
            source_file="access.log",
            event_category=EventCategory.WEB,
            event_action="http_request",
            severity=EventSeverity.INFORMATIONAL,
            url="/docs/union-agreements.html",
            raw_data="GET /docs/union-agreements.html HTTP/1.1",
        ),
    ]

    alerts = engine.run_detections(benign_events)
    assert len(alerts) == 0, f"Expected 0 alerts for benign URLs, got: {[a.title for a in alerts]}"


# =========================================================================
# Part 3: Evidence Confidence Formulas & Boundary Validation (B3)
# =========================================================================

def test_12_formula_heuristic_labeling_and_nan_rejection():
    """Confidence calculation docstring documents REDLOOP internal heuristic; rejects NaN and Inf."""
    doc = EvidenceConfidenceCalculator.__doc__ or ""
    assert "STANDARDS & COMPLIANCE NOTICE" in doc or "Internal Heuristic" in doc
    assert "NOT a FIRST" in doc or "NOT" in doc

    # Safe handling of NaN and Inf in confidence calculation
    res_nan = EvidenceConfidenceCalculator.calculate(
        verification_status=float("nan"),
        source_reliability=0.8,
        finding_freshness=0.9,
        tool_integrity=1.0,
    )
    assert not math.isnan(res_nan.score)
    assert 0.0 <= res_nan.score <= 1.0

    # EPSS boundary and NaN/Inf validation in IntelEngine
    assert VulnerabilityIntelligenceEngine._normalize_epss(None) is None
    assert VulnerabilityIntelligenceEngine._normalize_epss(float("nan")) is None
    assert VulnerabilityIntelligenceEngine._normalize_epss(float("inf")) is None
    assert VulnerabilityIntelligenceEngine._normalize_epss(float("-inf")) is None
    assert VulnerabilityIntelligenceEngine._normalize_epss(0.95) == 0.95
    assert VulnerabilityIntelligenceEngine._normalize_epss(97.5) == 0.975  # Percentage handling
    assert VulnerabilityIntelligenceEngine._normalize_epss(-0.5) == 0.0    # Clamped to minimum 0.0


# =========================================================================
# Part 4: Audit Trail Logging (B1)
# =========================================================================

def test_13_audit_trail_logging():
    """All capability approvals, executions, and rejections are logged to the audit database."""
    store = PlaybookApprovalStore.get_instance()
    
    # 1. Issue capability
    res_app = SOCPlaybookEngine.approve_step("PB-OUTBOUND", "step-out-2", approver="auditor_eve", approved=True)
    token = res_app["capability_token"]

    # 2. Execute capability
    SOCPlaybookEngine.execute_step("PB-OUTBOUND", "step-out-2", auth_token=token, operator="sec_ops_george")

    # 3. Attempt replay
    SOCPlaybookEngine.execute_step("PB-OUTBOUND", "step-out-2", auth_token=token, operator="sec_ops_george")

    # Verify audit events recorded in database
    conn = store._get_connection()
    try:
        events = conn.execute(
            "SELECT event_type, actor, status FROM playbook_audit_trail WHERE playbook_id = 'PB-OUTBOUND' ORDER BY timestamp ASC"
        ).fetchall()
        event_types = [e["event_type"] for e in events]
        assert "CAPABILITY_ISSUED" in event_types
        assert "STEP_EXECUTED" in event_types
        assert "REPLAY_ATTEMPT_BLOCKED" in event_types
    finally:
        conn.close()
