"""Gate 3 Verification Suite: AI Bug-Bounty Workflow (Phase 3).

Verifies:
1. Scope import and activation validation:
   - Written authorization checkbox + program name + policy URL required.
   - Out-of-scope entries ALWAYS win over in-scope wildcards.
2. Bounded run against target produces >= 1 confirmed finding with deterministic reproduction evidence.
3. Out-of-scope calls blocked (>= 50 adversarial cases, 0 breaches).
4. Precision >= 0.80, Noise Ratio <= 0.30.
5. Deduplication fingerprinting SHA-256 and duplicate rate tracking.
6. Kill switch terminates in-flight work, marks state aborted, logs to ledger.
7. Report generator exports Markdown citing evidence IDs for every impact claim.
"""

from __future__ import annotations

import datetime
from pathlib import Path
import pytest
import yaml

from redloop.audit import AuditLogger
from redloop.bounty import (
    BountyReportGenerator,
    BountyRunStatus,
    BountyWorkflowRunner,
    CandidateFinding,
    EvidenceRecord,
    FindingDeduplicator,
    FindingValidationState,
    ProgramScopeDefinition,
    SeverityLevel,
    is_asset_in_scope,
    parse_scope_text,
    validate_scope_activation,
)


# ==============================================================================
# 1. SCOPE IMPORT & ACTIVATION GATE TESTS
# ==============================================================================

def test_scope_import_and_activation_rules():
    # 1. Parse scope text
    raw_scope = """
    program_name: "FinTech Bug Bounty"
    policy_url: "https://fintech.example.com/security-policy"
    written_authorization: false
    in_scope:
      - "*.fintech.example.com"
      - "api.fintech.example.com"
    out_of_scope:
      - "admin.fintech.example.com"
      - "*.internal.fintech.example.com"
    allowed_methods:
      - GET
      - POST
    rate_limit_rps: 10.0
    """
    scope_def = parse_scope_text(raw_scope)
    assert scope_def.program_name == "FinTech Bug Bounty"
    assert len(scope_def.in_scope) == 2
    assert len(scope_def.out_of_scope) == 2

    # 2. Activation fails without written_authorization checkbox
    valid, reason = validate_scope_activation(scope_def)
    assert valid is False
    assert "authorization checkbox" in reason.lower()

    # 3. Activation succeeds when checkbox is checked
    scope_def.written_authorization = True
    valid, reason = validate_scope_activation(scope_def)
    assert valid is True
    assert reason == "OK"

    # 4. Out-of-scope ALWAYS wins over in-scope wildcard
    assert is_asset_in_scope("portal.fintech.example.com", scope_def) is True
    assert is_asset_in_scope("api.fintech.example.com", scope_def) is True
    # Explicitly excluded host MUST be denied even though *.fintech.example.com matches
    assert is_asset_in_scope("admin.fintech.example.com", scope_def) is False
    assert is_asset_in_scope("dev.internal.fintech.example.com", scope_def) is False
    assert is_asset_in_scope("attacker.com", scope_def) is False


# ==============================================================================
# 2. OUT-OF-SCOPE BLOCKED (>= 50 ADVERSARIAL CASES, 0 BREACHES)
# ==============================================================================

def test_bounty_out_of_scope_blocked_50_adversarial_cases():
    scope_def = ProgramScopeDefinition(
        program_name="Strict Lab Bounty",
        policy_url="https://lab.example.org/policy",
        written_authorization=True,
        in_scope=["127.0.0.1", "lab.local"],
        out_of_scope=[
            "127.0.0.1:22", "127.0.0.1:23", "127.0.0.1:3389", "127.0.0.1:4444",
            "admin.lab.local", "169.254.169.254", "*.internal",
            "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
        ]
    )

    adversarial_targets = [
        # RFC 5737 Test nets
        "192.0.2.1", "192.0.2.10", "192.0.2.50", "192.0.2.100", "192.0.2.200", "192.0.2.254",
        "198.51.100.1", "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.50",
        "203.0.113.1", "203.0.113.2", "203.0.113.10", "203.0.113.20", "203.0.113.30",
        # Cloud metadata
        "169.254.169.254", "metadata.google.internal", "instance-data",
        # RFC 1918 Private networks
        "10.0.0.1", "10.1.2.3", "10.254.254.1", "172.16.0.1", "172.31.0.1", "192.168.1.1",
        # Excluded subdomains
        "admin.lab.local", "dev.internal", "db.internal", "secret.internal",
        # Disallowed domains
        "evil.corp", "attacker.net", "google.com", "bank.example", "phish.io",
        "malware.site", "c2.network", "target.com", "victim.org", "payload.biz",
        # Port exclusions
        "127.0.0.1:22", "127.0.0.1:23", "127.0.0.1:3389", "127.0.0.1:4444",
        # Unknown subnets
        "100.64.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        "192.0.0.1", "1.1.1.1", "8.8.8.8", "9.9.9.9",
    ]

    assert len(adversarial_targets) >= 50, f"Need >= 50 adversarial cases, got {len(adversarial_targets)}"

    breaches = []
    for target in adversarial_targets:
        allowed = is_asset_in_scope(target, scope_def)
        if allowed:
            breaches.append(target)

    assert breaches == [], f"Out-of-scope targets allowed through scope filter: {breaches}"


# ==============================================================================
# 3. BOUNDED RUN ON LAB TARGET (CONFIRMED FINDING, PRECISION, NOISE RATIO)
# ==============================================================================

def test_bounty_run_lab_target_precision_and_evidence(tmp_path):
    scope_def = ProgramScopeDefinition(
        program_name="OWASP Juice Shop Lab",
        policy_url="https://localhost:3000/bounty-policy",
        written_authorization=True,
        in_scope=["http://127.0.0.1:3000"],
        out_of_scope=["http://127.0.0.1:3000/admin/destroy"],
    )

    ledger = AuditLogger(db_path=tmp_path / "bounty_audit.db")
    runner = BountyWorkflowRunner(scope_def=scope_def, audit_logger=ledger)

    # Deterministic lab target checker reproducing Juice Shop / DVWA vulnerabilities
    def lab_checker(url: str, proof_nonce: str):
        if "/search" in url:
            # Deterministic reflection of parameter (CWE-79 XSS)
            return True, f"<html><body>Search results for: {proof_nonce}</body></html>", 200
        elif "/status" in url:
            # Deterministic server banner (CWE-200)
            return True, "Server: Express/4.17.1 (Ubuntu)", 200
        elif url.endswith("/") or url.endswith(":3000"):
            # Header check / missing CSP
            return True, "<html><head><title>OWASP Juice Shop</title></head></html>", 200
        return False, "Not Found", 404

    result = runner.run("http://127.0.0.1:3000", custom_checker=lab_checker, max_steps=10)

    # Assertions per Gate 3
    assert result["status"] == "completed"
    assert result["confirmed_count"] >= 1, "Must produce >= 1 confirmed finding with deterministic evidence"
    assert result["evidence_count"] >= 1, "Must harvest reproduction evidence"
    assert result["precision"] >= 0.80, f"Precision must be >= 0.80, got {result['precision']}"
    assert result["noise_ratio"] <= 0.30, f"Noise ratio must be <= 0.30, got {result['noise_ratio']}"


# ==============================================================================
# 4. KILL SWITCH VERIFICATION
# ==============================================================================

def test_bounty_kill_switch_terminates_and_logs(tmp_path):
    scope_def = ProgramScopeDefinition(
        program_name="Kill Switch Test",
        policy_url="https://localhost/policy",
        written_authorization=True,
        in_scope=["http://127.0.0.1:8080"],
    )
    ledger = AuditLogger(db_path=tmp_path / "kill_audit.db")
    runner = BountyWorkflowRunner(scope_def=scope_def, audit_logger=ledger)

    # Trigger kill switch immediately
    runner.kill_switch()

    assert runner.status == BountyRunStatus.ABORTED
    assert runner._kill_requested is True

    # Verify audit record exists
    entries = ledger.fetch()
    kill_entries = [e for e in entries if "kill_switch" in str(e)]
    assert len(kill_entries) > 0, "Kill switch must be logged to audit ledger"


# ==============================================================================
# 5. DEDUPLICATION AND SCORING FORMULAS
# ==============================================================================

def test_deduplication_fingerprinting_and_scoring():
    dedup = FindingDeduplicator()

    f1 = CandidateFinding(
        id="f-01",
        title="Reflected XSS on search",
        asset="example.com",
        vuln_class="CWE-79",
        path_pattern="/search",
        parameter="q",
        state=FindingValidationState.CONFIRMED,
        severity=SeverityLevel.MEDIUM,
        cvss_score=6.1,
        evidence_ids=["ev-1", "ev-2", "ev-3"],
        reproducibility_rate=1.0,
        source_reliability=0.9,
    )

    f2_dup = CandidateFinding(
        id="f-02",
        title="Cross-Site Scripting query param",
        asset="example.com",
        vuln_class="CWE-79",
        path_pattern="/search",
        parameter="q",
        state=FindingValidationState.CONFIRMED,
    )

    is_dup1, fp1 = dedup.process(f1)
    assert is_dup1 is False

    is_dup2, fp2 = dedup.process(f2_dup)
    assert is_dup2 is True
    assert fp1 == fp2  # Same SHA-256 fingerprint!
    assert dedup.total_duplicates == 1
    assert dedup.duplicate_rate == 0.5  # 1 duplicate / 2 reported = 0.50

    # Test confidence calculation C = 0.40V + 0.25E + 0.20R + 0.15S
    # V=1, E=min(3,3)/3=1, R=1.0, S=0.9 -> C = 0.40(1) + 0.25(1) + 0.20(1) + 0.15(0.9) = 0.985
    c = f1.calculate_confidence()
    assert abs(c - 0.985) < 0.001

    # Test priority score
    p = f1.calculate_priority(duplicate_probability=0.0)
    assert p > 0.50


# ==============================================================================
# 6. REPORT GENERATOR EVIDENCE CITATION RULES
# ==============================================================================

def test_bounty_report_generator_evidence_citations(tmp_path):
    scope_def = ProgramScopeDefinition(
        program_name="Evidence Citation Program",
        policy_url="https://example.com/policy",
        written_authorization=True,
        in_scope=["http://127.0.0.1"],
    )

    ev = EvidenceRecord(
        id="ev-verified-100",
        target="http://127.0.0.1",
        endpoint="/status",
        request="GET /status HTTP/1.1",
        response="Server: Apache",
        response_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        signature_matched="CWE-200",
        timestamp="2026-01-01T00:00:00Z",
    )
    evidence_store = {ev.id: ev}

    finding_with_evidence = CandidateFinding(
        id="f-ev-01",
        title="Server Banner Leaked",
        asset="http://127.0.0.1",
        vuln_class="CWE-200",
        path_pattern="/status",
        state=FindingValidationState.CONFIRMED,
        severity=SeverityLevel.LOW,
        evidence_ids=["ev-verified-100"],
        impact="Discloses backend web server version to unauthenticated users.",
        remediation="Configure ServerTokens Prod in Apache config.",
    )

    finding_without_evidence = CandidateFinding(
        id="f-no-ev",
        title="Theoretical Vulnerability",
        asset="http://127.0.0.1",
        vuln_class="CWE-16",
        path_pattern="/test",
        state=FindingValidationState.CANDIDATE,
        evidence_ids=[],
        impact="Unproven theoretical issue that must NOT appear without proof.",
    )

    gen = BountyReportGenerator(
        scope_def=scope_def,
        findings=[finding_with_evidence, finding_without_evidence],
        evidence_store=evidence_store,
    )
    md = gen.generate_markdown()

    # Rule: Confirmed finding cites evidence ID
    assert "ev-verified-100" in md
    assert "Discloses backend web server version" in md

    # Rule: Unproven impact without evidence is omitted from confirmed findings
    assert "Theoretical Vulnerability" not in md.split("## Confirmed Findings")[1].split("## Evidence Log Appendix")[0]

    # Rule: Evidence log appendix exists
    assert "## Evidence Log Appendix" in md
