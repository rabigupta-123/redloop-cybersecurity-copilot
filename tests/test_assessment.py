"""Comprehensive unit, integration, and negative test suite for RedLoop Assessment Engine.

Covers:
- Section 40: Unit, integration, and negative tests.
- Scope guard & machine-enforced authorization.
- Finding normalization, Evidence SHA-256 integrity.
- Risk calculation & Attack Surface correlation.
- File triage, Config analysis, Host security (LOCAL_HOST vs REMOTE_HOST).
- Assessment pipeline execution, Checkpointing & Resume.
- Reporting generation.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from redloop.assessment.capability import get_capabilities
from redloop.assessment.config_engine import ConfigEngine
from redloop.assessment.correlation import AttackSurfaceCorrelator
from redloop.assessment.engine import AssessmentEngine, AssessmentStore
from redloop.assessment.file_engine import FileTriageEngine, compute_entropy
from redloop.assessment.host_engine import HostEngine, is_local_target
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageStatus,
)
from redloop.assessment.reporting import ReportingEngine
from redloop.assessment.risk import calculate_risk
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.software_engine import SoftwareEngine
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def test_scope(tmp_path):
    """Create a signed scope authorizing 127.0.0.1 and ports 80, 443, 8080."""
    today = date.today()
    scope_data = {
        "version": 1,
        "id": "unit-test-assessment",
        "authorized_by": "unit-tests",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback-ip",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": [
                    "scan",
                    "check",
                    "assess",
                    "web_test",
                    "web_check",
                    "tls_check",
                    "dns_check",
                    "api_check",
                    "file_triage",
                    "config_security",
                    "host_security",
                ],
                "ports": [80, 443, 8080, 8765],
            },
            {
                "domain": "localhost",
                "label": "loopback-domain",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": [
                    "scan",
                    "check",
                    "assess",
                    "web_test",
                    "web_check",
                    "tls_check",
                    "dns_check",
                    "api_check",
                    "file_triage",
                    "config_security",
                    "host_security",
                ],
                "ports": [80, 443, 8080, 8765],
            },
        ],
    }
    secret = "test-secret-key-32-bytes-long-string!"
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    return ScopeManager(scope_file, secret)


@pytest.fixture
def audit_log(tmp_path):
    return AuditLogger(tmp_path / "audit.db")


# ============================================================================
# 1. SCOPE GUARD TESTS (Machine-enforced, No conversational friction)
# ============================================================================
def test_scope_guard_valid_target_passes(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    # 127.0.0.1 is in scope
    guard.verify_operation(target="127.0.0.1", port=80, operation_class=OperationClass.READ_ONLY)


def test_scope_guard_out_of_scope_target_blocked(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError, match="not present in scope|refusing to act|Scope blocked"):
        guard.verify_operation(target="unauthorized.target.com", operation_class=OperationClass.READ_ONLY)


@pytest.mark.parametrize(
    "label",
    [
        "sample_binary",
        "config_artifact",
        "docker_test",
        "compose_test",
        "local_artifact",
    ],
)
def test_scope_guard_rejects_name_based_scope_bypass(test_scope, audit_log, label):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError):
        guard.verify_operation(
            target=label, operation_class=OperationClass.READ_ONLY
        )


def test_scope_guard_unknown_action_is_denied_without_fallback(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError, match="not permitted|Scope blocked"):
        guard.is_target_authorized("127.0.0.1", "totally_unknown_action", port=80)


def test_scope_guard_port_scoped_action_requires_explicit_port(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError, match="no port was specified|Scope blocked"):
        guard.is_target_authorized("127.0.0.1", "scan")


def test_scope_guard_unauthorized_port_blocked(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError, match="port 22 is not explicitly authorized|Scope blocked"):
        guard.verify_operation(target="127.0.0.1", port=22, operation_class=OperationClass.READ_ONLY)


def test_scope_guard_unauthorized_operation_class_blocked(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    with pytest.raises(ScopeBlockedError, match="DESTRUCTIVE"):
        guard.verify_operation(target="127.0.0.1", port=80, operation_class=OperationClass.DESTRUCTIVE)


# ============================================================================
# 2. EVIDENCE & FINDINGS TESTS (Verifiable SHA-256 Hashes & Schema)
# ============================================================================
def test_evidence_integrity_hash():
    ev = Evidence(
        target="127.0.0.1",
        request_metadata={"method": "GET", "path": "/"},
        response_metadata={"status_code": 200},
        response_excerpt="Server: Nginx",
        tool_output="HTTP/1.1 200 OK",
    )
    assert len(ev.sha256_hash) == 64
    # Every integrity-relevant field participates in the canonical pre-image.
    canonical = json.dumps(
        {
            "id": ev.id,
            "timestamp": ev.timestamp,
            "operation_id": ev.operation_id,
            "target": ev.target,
            "provenance": ev.provenance.value,
            "source": ev.source,
            "source_task_id": ev.source_task_id,
            "request": ev.request_metadata,
            "response": ev.response_metadata,
            "excerpt": ev.response_excerpt,
            "tool_output": ev.tool_output,
            "parser_result": ev.parser_result,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert ev.sha256_hash == expected_hash
    assert ev.verify_integrity() is True

    # Tampering with any previously-unhashed field must invalidate the digest.
    ev.operation_id = "op-tampered"
    assert ev.verify_integrity() is False


def test_finding_and_risk_scoring():
    f = Finding(
        title="Cleartext HTTP Transmission",
        category="tls_security",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        asset="127.0.0.1",
        target="127.0.0.1",
        port=80,
        description="Port 80 does not enforce TLS.",
    )
    score, assigned_sev, rationale = calculate_risk(
        finding=f,
        is_internet_facing=True,
        asset_criticality=1.0,
        is_chained=True,
    )
    assert 7.0 <= score <= 10.0
    assert assigned_sev in (Severity.HIGH, Severity.CRITICAL)
    assert "Base: 7.5" in rationale
    assert "Chained" in rationale


# ============================================================================
# 3. ATTACK SURFACE GRAPH & CORRELATION
# ============================================================================
def test_attack_surface_graph_and_chains():
    correlator = AttackSurfaceCorrelator()
    findings = [
        Finding(
            id="RL-TLS-01",
            title="Deprecated TLS Protocol",
            category="tls_security",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            asset="127.0.0.1",
            target="127.0.0.1",
            port=443,
            description="TLS 1.0 active",
        ),
        Finding(
            id="RL-AUTH-01",
            title="Exposed Administrative Login Endpoint",
            category="authentication_security",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            asset="127.0.0.1",
            target="127.0.0.1",
            port=443,
            endpoint="/admin",
            description="Login page exposed",
        ),
    ]

    graph = correlator.build_graph("127.0.0.1", findings)
    assert len(graph.nodes) >= 3  # host, port, findings
    assert len(graph.edges) >= 2

    chains = correlator.detect_attack_chains(findings)
    assert len(chains) == 1
    assert "Weak Transport" in chains[0]["name"]
    assert "RL-TLS-01" in chains[0]["finding_ids"]
    assert "RL-AUTH-01" in chains[0]["finding_ids"]


# ============================================================================
# 4. CAPABILITY MATRIX & RUNTIME DISCOVERY
# ============================================================================
def test_capability_matrix():
    matrix = get_capabilities()
    assert isinstance(matrix.tools, dict)
    assert "nmap" in matrix.tools
    assert "curl" in matrix.tools
    assert "docker" in matrix.tools


# ============================================================================
# 5. SOFTWARE / VERSION INTELLIGENCE
# ============================================================================
def test_software_normalization_and_offline_intelligence():
    engine = SoftwareEngine()
    comp = engine.normalize_component("nginx/1.24.0 (Ubuntu)")
    assert comp.product == "nginx"
    assert comp.version == "1.24.0"
    assert comp.vendor == "F5 / NGINX"

    # Offline feed returns UNAVAILABLE rather than inventing CVEs (Section 16)
    status, records = engine.lookup_vulnerabilities(comp)
    assert status == "UNAVAILABLE"
    assert records == []


# ============================================================================
# 6. STATIC FILE TRIAGE
# ============================================================================
def test_file_triage_entropy_and_ioc(tmp_path, test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    engine = FileTriageEngine(guard, audit_log)

    sample_file = tmp_path / "sample_binary.bin"
    sample_content = (
        b"MZ\x90\x00\x03\x00\x00\x00"  # PE signature stub
        b"http://c2-malicious.domain.com/beacon\x00"
        b"198.51.100.24\x00"
        + b"\x00" * 50
        + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    )
    sample_file.write_bytes(sample_content)

    res = engine.triage_file(sample_file, target_label="127.0.0.1")
    assert res.status == StageStatus.SUCCESS
    assert len(res.findings) >= 1
    ioc_finding = next((f for f in res.findings if "Embedded Network Indicators" in f.title), None)
    assert ioc_finding is not None
    assert "198.51.100.24" in res.data["extracted_ips"]


# ============================================================================
# 7. STATIC CONFIGURATION & CONTAINER AUDIT
# ============================================================================
def test_config_engine_dockerfile(tmp_path, test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    engine = ConfigEngine(guard, audit_log)

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.18\n"
        "ENV API_SECRET_KEY=supersecret1234\n"
        "CMD ['sh']\n",
        encoding="utf-8",
    )

    res = engine.audit_config_file(dockerfile, target_label="127.0.0.1")
    assert res.status == StageStatus.SUCCESS
    titles = [f.title for f in res.findings]
    assert any("Hardcoded Credential in Dockerfile" in t for t in titles)
    assert any("Container Runs As Root User" in t for t in titles)


def test_config_engine_docker_compose_privileged(tmp_path, test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    engine = ConfigEngine(guard, audit_log)

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "version: '3.8'\n"
        "services:\n"
        "  app:\n"
        "    image: web\n"
        "    privileged: true\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    res = engine.audit_config_file(compose, target_label="127.0.0.1")
    assert res.status == StageStatus.SUCCESS
    titles = [f.title for f in res.findings]
    assert any("Privileged Mode" in t for t in titles)
    assert any("Dangerous Host Filesystem Mount" in t for t in titles)


# ============================================================================
# 8. HOST SECURITY (Separating LOCAL_HOST from REMOTE_HOST)
# ============================================================================
def test_host_engine_remote_target_unavailable(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    engine = HostEngine(guard, audit_log)

    # Remote target must return UNAVAILABLE without performing local commands
    res = engine.assess_host("example.com")
    assert res.status == StageStatus.UNAVAILABLE
    assert "Target is REMOTE_HOST" in res.reason


def test_host_engine_local_target(test_scope, audit_log):
    guard = AssessmentScopeGuard(test_scope, audit_log)
    engine = HostEngine(guard, audit_log)

    assert is_local_target("127.0.0.1") is True
    assert is_local_target("localhost") is True
    assert is_local_target("8.8.8.8") is False

    res = engine.assess_host("127.0.0.1")
    assert res.status == StageStatus.SUCCESS
    assert res.data["target_type"] == "LOCAL_HOST"


# ============================================================================
# 9. ASSESSMENT CHECKPOINT & RESUME STORE
# ============================================================================
def test_assessment_store_save_load_resume(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.sqlite")
    state = AssessmentState(
        id="asmt-test-1234",
        target="127.0.0.1",
        depth=AssessmentDepth.QUICK,
        status="RUNNING",
        current_stage="network_discovery",
    )
    store.save(state)

    loaded = store.load("asmt-test-1234")
    assert loaded is not None
    assert loaded.id == "asmt-test-1234"
    assert loaded.target == "127.0.0.1"
    assert loaded.current_stage == "network_discovery"

    # Update stage & save
    loaded.completed_stages["scope_validation"] = {"status": "SUCCESS"}
    store.save(loaded)

    reloaded = store.load("asmt-test-1234")
    assert "scope_validation" in reloaded.completed_stages


# ============================================================================
# 10. REPORTING ENGINE
# ============================================================================
def test_reporting_engine_all_variants(tmp_path):
    state = AssessmentState(
        id="asmt-report-test",
        target="127.0.0.1",
        depth=AssessmentDepth.STANDARD,
        status="COMPLETED",
        findings=[
            Finding(
                id="RL-REP-01",
                title="Sample Vulnerability Finding",
                category="web_security",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                asset="127.0.0.1",
                target="127.0.0.1",
                port=80,
                description="Testing report formatting.",
                risk_score=7.8,
                risk_explanation="Deterministic formula test.",
            )
        ],
        evidence=[
            Evidence(
                target="127.0.0.1",
                tool_output="Sample tool output",
                response_excerpt="HTTP/1.1 200 OK",
            )
        ],
    )

    engine = ReportingEngine()
    paths = engine.export_all(state, tmp_path / "reports")

    assert paths["executive"].exists()
    assert paths["technical"].exists()
    assert paths["attack_surface"].exists()
    assert paths["evidence"].exists()

    exec_txt = paths["executive"].read_text(encoding="utf-8")
    assert "Executive Security Assessment Report" in exec_txt
    assert "Risk Scorecard" in exec_txt

    tech_txt = paths["technical"].read_text(encoding="utf-8")
    assert "Sample Vulnerability Finding" in tech_txt
    assert "Deterministic formula test." in tech_txt
