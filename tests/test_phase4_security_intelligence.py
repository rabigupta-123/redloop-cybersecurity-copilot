"""Phase 4 Automated Verification Suite: Deep Security Intelligence & Analysis Engine.

Comprehensive testing of:
1.  Universal Finding Normalization (Nmap parser, ports, services, versions)
2.  Universal Finding Normalization (HTTP headers, HSTS, CSP, server banner disclosure)
3.  Truthful deduplication based on stable cryptographic fingerprints
4.  Multi-source evidence merging and verification elevation
5.  Authoritative Vulnerability Intelligence lookup (CVE-2021-44228 Log4Shell)
6.  CISA Known Exploited Vulnerabilities (KEV) flag and tagging
7.  FIRST Exploit Prediction Scoring System (EPSS) probability extraction
8.  Unknown CVE graceful handling (truthful status, no hallucinations)
9.  Validation Engine: Linux distribution backport patch detection (Debian/Ubuntu)
10. Validation Engine: Multi-source corroboration elevation to CONFIRMED
11. Validation Engine: False-positive evaluation and explainable rationale
12. Asset Attack Graph: Node taxonomy and properties (10 node types)
13. Asset Attack Graph: Edge relations and directed graph topology
14. Asset Attack Graph: Cytoscape JSON serialization
15. Deterministic Attack Path synthesis and likelihood derivation
16. Composite Risk Scoring: CVSS + EPSS multiplier + CISA KEV boost + verification weight
17. Operational Priority assignment (P1 Critical Immediate through P5 Informational)
18. Technology-aware Remediation guidance (containment, fix, config, validation, rollback)
19. Professional Report Generation: Structured JSON output and summary metrics
20. Professional Report Generation: Audit-grade Executive & Technical Markdown
21. Professional Report Generation: Standalone HTML5 document with embedded styling
22. REST API Contract: GET /api/findings with filtering
23. REST API Contract: GET /api/findings/{id} and POST /api/findings/{id}/validate
24. REST API Contract: GET /api/intelligence/cve/{cve_id} and GET /api/intelligence/epss/{cve_id}
25. REST API Contract: GET /api/assets/graph and GET /api/attack-paths
26. REST API Contract: GET /api/analytics/risk and GET /api/reports/{task_id}
"""

import json
import pytest
from starlette.testclient import TestClient

from redloop.assessment.asset_attack_graph import (
    AssetAttackGraph,
    AttackPath,
    EdgeRelation,
    GraphEdge,
    GraphNode,
    NodeType,
)
from redloop.assessment.finding_models import (
    FalsePositiveAnalysis,
    Finding,
    FindingNormalizer,
    FindingRemediation,
    FindingSeverity,
    FindingStore,
    FindingType,
    OperationalPriority,
    VerificationStatus,
)
from redloop.assessment.intel_engine import (
    IntelligenceProviderStatus,
    VulnerabilityIntelligenceEngine,
    VulnerabilityRecord,
)
from redloop.assessment.risk_remediation import (
    RemediationIntelligenceEngine,
    RiskAnalyticsEngine,
)
from redloop.assessment.validation_engine import FindingValidationEngine
from redloop.assessment.phase4_reports import Phase4ReportGenerator


# =========================================================================
# Part 1: Finding Normalization & Deduplication
# =========================================================================

def test_01_nmap_normalization():
    raw_nmap = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-03 23:00 UTC
Nmap scan report for 127.0.0.1
Host is up (0.00012s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
8080/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.11.4)
"""
    findings = FindingNormalizer.normalize_nmap(
        raw_stdout=raw_nmap,
        target="127.0.0.1",
        task_id="task-test-nmap",
        evidence_id="evi-nmap-01",
    )
    assert len(findings) == 3
    ports = [f.port for f in findings]
    assert 22 in ports
    assert 80 in ports
    assert 8080 in ports

    ssh_f = next(f for f in findings if f.port == 22)
    assert ssh_f.affected_component == "ssh"
    assert "OpenSSH" in (ssh_f.affected_version or "")
    assert ssh_f.raw_evidence_id == "evi-nmap-01"
    assert ssh_f.verification_status == VerificationStatus.SUPPORTED


def test_02_http_header_normalization():
    raw_headers = """HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 23:00:00 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 1024
Connection: keep-alive
"""
    findings = FindingNormalizer.normalize_http_headers(
        raw_headers=raw_headers,
        target="127.0.0.1",
        task_id="task-test-headers",
        evidence_id="evi-hdr-01",
    )
    # Expect 4 missing security headers + 1 banner disclosure = 5
    assert len(findings) == 5
    titles = [f.title for f in findings]
    assert any("HSTS" in t for t in titles)
    assert any("CSP" in t or "Content Security Policy" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Banner Disclosed" in t for t in titles)


def test_03_finding_deduplication_by_fingerprint():
    f1 = Finding(
        finding_id="fnd-1",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 80/tcp (http)",
        description="HTTP web server",
        severity=FindingSeverity.LOW,
        port=80,
        protocol="tcp",
        affected_component="http",
    )
    f2 = Finding(
        finding_id="fnd-2",
        task_id="task-2",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 80/tcp (http)",
        description="HTTP web server detected in second scan",
        severity=FindingSeverity.LOW,
        port=80,
        protocol="tcp",
        affected_component="http",
    )
    assert f1.fingerprint == f2.fingerprint
    deduped = FindingNormalizer.deduplicate([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].finding_id == "fnd-1"


def test_04_corroborating_evidence_merge():
    f1 = Finding(
        finding_id="fnd-1",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 443/tcp (https)",
        description="HTTPS port",
        severity=FindingSeverity.LOW,
        port=443,
        protocol="tcp",
        affected_component="https",
        source_tool="nmap",
        raw_evidence_id="evi-nmap-1",
    )
    f2 = Finding(
        finding_id="fnd-2",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 443/tcp (https)",
        description="HTTPS port confirmed by curl",
        severity=FindingSeverity.LOW,
        port=443,
        protocol="tcp",
        affected_component="https",
        source_tool="curl",
        raw_evidence_id="evi-curl-2",
    )
    deduped = FindingNormalizer.deduplicate([f1, f2])
    assert len(deduped) == 1
    merged = deduped[0]
    assert merged.verification_status == VerificationStatus.CORROBORATED
    assert "corroborating_evidences" in merged.metadata
    assert "evi-curl-2" in merged.metadata["corroborating_evidences"]


# =========================================================================
# Part 2: Vulnerability Intelligence
# =========================================================================

def test_05_cve_intelligence_lookup_known():
    engine = VulnerabilityIntelligenceEngine.get_instance()
    rec = engine.get_cve_intel("CVE-2021-44228")
    assert rec.cve_id == "CVE-2021-44228"
    assert "Log4j" in rec.title
    assert rec.cvss_v31_score == 10.0
    assert rec.provider_status == IntelligenceProviderStatus.AVAILABLE


def test_06_cisa_kev_flagging():
    engine = VulnerabilityIntelligenceEngine.get_instance()
    rec = engine.get_cve_intel("CVE-2021-41773")
    assert rec.cisa_kev is True
    assert rec.cisa_kev_date_added == "2021-11-03"


def test_07_epss_scoring():
    engine = VulnerabilityIntelligenceEngine.get_instance()
    rec = engine.get_cve_intel("CVE-2021-44228")
    assert rec.epss_score is not None
    assert rec.epss_score > 0.90
    assert rec.epss_percentile is not None
    assert rec.epss_percentile > 0.95


def test_08_unknown_cve_graceful_fallback():
    engine = VulnerabilityIntelligenceEngine.get_instance()
    rec = engine.get_cve_intel("CVE-2099-99999")
    assert rec.cve_id == "CVE-2099-99999"
    assert rec.cvss_v31_score is None
    assert rec.cisa_kev is False
    assert rec.provider_status == IntelligenceProviderStatus.NOT_QUERIED


# =========================================================================
# Part 3: Finding Validation & False Positive Engine
# =========================================================================

def test_09_validation_distro_backport_detection():
    f = Finding(
        finding_id="fnd-backport",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.VULNERABILITY,
        title="Apache HTTP Server Vulnerability",
        description="Vulnerable version detected",
        severity=FindingSeverity.HIGH,
        affected_component="apache2",
        affected_version="2.4.41-4ubuntu3.14",
        cve_ids=["CVE-2021-41773"],
    )
    validated = FindingValidationEngine.validate_finding(f)
    assert validated.verification_status in (VerificationStatus.CONTRADICTED, VerificationStatus.FALSE_POSITIVE)
    assert validated.false_positive_status.likelihood > 0.5
    assert any("backported" in e for e in validated.false_positive_status.contradicting_evidence)


def test_10_validation_multi_source_elevation():
    f = Finding(
        finding_id="fnd-elevated",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 22/tcp (ssh)",
        description="SSH service",
        severity=FindingSeverity.LOW,
        metadata={"corroborating_evidences": ["evi-1", "evi-2"]},
    )
    validated = FindingValidationEngine.validate_finding(f)
    assert validated.verification_status == VerificationStatus.CONFIRMED
    assert validated.confidence >= 0.9


def test_11_validation_false_positive_analysis():
    analysis = FalsePositiveAnalysis(
        likelihood=0.75,
        is_false_positive=False,
        confidence_basis="Distro banner analysis",
        contradicting_evidence=["Patch applied via ubuntu security update"],
        recommended_action="Inspect changelog",
    )
    d = analysis.to_dict()
    assert d["likelihood"] == 0.75
    assert "changelog" in d["recommended_action"]


# =========================================================================
# Part 4: Asset Attack Graph & Attack Path Analysis
# =========================================================================

def test_12_asset_attack_graph_node_types():
    graph = AssetAttackGraph("127.0.0.1")
    n1 = GraphNode("host:127.0.0.1", NodeType.HOST, "127.0.0.1")
    n2 = GraphNode("svc:127.0.0.1:80", NodeType.SERVICE, "HTTP Service", {"port": 80})
    graph.add_node(n1)
    graph.add_node(n2)
    assert len(graph.nodes) == 2
    assert "host:127.0.0.1" in graph.nodes


def test_13_asset_attack_graph_edge_relations():
    graph = AssetAttackGraph("127.0.0.1")
    graph.add_node(GraphNode("host:127.0.0.1", NodeType.HOST, "127.0.0.1"))
    graph.add_node(GraphNode("svc:127.0.0.1:80", NodeType.SERVICE, "HTTP Service"))
    graph.add_edge(GraphEdge("host:127.0.0.1", "svc:127.0.0.1:80", EdgeRelation.EXPOSES))
    assert len(graph.edges) == 1
    assert graph.edges[0].relation == EdgeRelation.EXPOSES


def test_14_asset_attack_graph_cytoscape_export():
    graph = AssetAttackGraph("127.0.0.1")
    graph.add_node(GraphNode("host:127.0.0.1", NodeType.HOST, "127.0.0.1"))
    graph.add_node(GraphNode("svc:127.0.0.1:80", NodeType.SERVICE, "HTTP Service"))
    graph.add_edge(GraphEdge("host:127.0.0.1", "svc:127.0.0.1:80", EdgeRelation.EXPOSES))
    cy = graph.export_cytoscape()
    assert "elements" in cy
    assert "nodes" in cy["elements"]
    assert "edges" in cy["elements"]
    assert len(cy["elements"]["nodes"]) == 2
    assert len(cy["elements"]["edges"]) == 1


def test_15_attack_path_derivation():
    graph = AssetAttackGraph("127.0.0.1")
    # Simulate a web entry point exposing a vulnerable service leading to admin access
    graph.add_node(GraphNode("host:127.0.0.1", NodeType.HOST, "127.0.0.1"))
    graph.add_node(GraphNode("svc:127.0.0.1:80", NodeType.SERVICE, "HTTP Server", {"port": 80}))
    graph.add_node(GraphNode("vuln:log4j", NodeType.VULNERABILITY, "Log4Shell RCE"))
    graph.add_edge(GraphEdge("host:127.0.0.1", "svc:127.0.0.1:80", EdgeRelation.EXPOSES))
    graph.add_edge(GraphEdge("svc:127.0.0.1:80", "vuln:log4j", EdgeRelation.HAS_FINDING))

    paths = graph.derive_attack_paths()
    assert len(paths) >= 1
    p = paths[0]
    assert p.entry_node_id == "host:127.0.0.1"
    assert p.target_node_id == "vuln:log4j"
    assert len(p.path_nodes) == 3


# =========================================================================
# Part 5: Risk Analytics & Remediation Intelligence
# =========================================================================

def test_16_risk_scoring_composite_formula():
    f = Finding(
        finding_id="fnd-risk-1",
        task_id="task-risk",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.VULNERABILITY,
        title="Apache Log4j RCE",
        description="Critical exploit",
        severity=FindingSeverity.CRITICAL,
        cvss_score=10.0,
        cisa_kev=True,
        epss_score=0.97,
        verification_status=VerificationStatus.CONFIRMED,
    )
    score, priority, breakdown = RiskAnalyticsEngine.calculate_risk(f)
    assert score >= 90.0
    assert priority == OperationalPriority.P1_CRITICAL_IMMEDIATE
    assert breakdown["kev_multiplier"] == 1.35
    assert breakdown["epss_multiplier"] > 1.25


def test_17_operational_priority_assignment():
    f_p5 = Finding(
        finding_id="fnd-p5",
        task_id="task-p5",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 80/tcp",
        description="Standard HTTP port",
        severity=FindingSeverity.LOW,
        cvss_score=2.0,
        verification_status=VerificationStatus.SUPPORTED,
    )
    score, priority, _ = RiskAnalyticsEngine.calculate_risk(f_p5)
    assert priority in (OperationalPriority.P4_LOW_BACKLOG, OperationalPriority.P5_INFORMATIONAL)


def test_18_remediation_intelligence_technology_guidance():
    f_ssh = Finding(
        finding_id="fnd-ssh",
        task_id="task-rem",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.MISCONFIGURATION,
        title="SSH Legacy Ciphers Enabled",
        description="Weak SSH configuration",
        severity=FindingSeverity.MEDIUM,
    )
    enriched = RemediationIntelligenceEngine.enrich_finding(f_ssh)
    assert enriched.remediation is not None
    assert "bastion" in enriched.remediation.immediate_containment
    assert "sshd_config" in enriched.remediation.permanent_fix
    assert "KexAlgorithms" in (enriched.remediation.configuration_snippet or "")
    assert "rollback" in enriched.remediation.rollback_plan.lower() or "revert" in enriched.remediation.rollback_plan.lower() or "rm" in enriched.remediation.rollback_plan.lower()


# =========================================================================
# Part 6: Report Generation Engine
# =========================================================================

def test_19_report_generator_json():
    f = Finding(
        finding_id="fnd-rep-1",
        task_id="task-rep",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 22/tcp (ssh)",
        description="SSH port open",
        severity=FindingSeverity.LOW,
        operational_priority=OperationalPriority.P4_LOW_BACKLOG,
    )
    gen = Phase4ReportGenerator("127.0.0.1", "task-rep", [f])
    rep = gen.generate_json()
    assert rep["report_version"] == "4.0"
    assert rep["summary"]["total_findings"] == 1
    assert "findings" in rep
    assert "asset_graph" in rep


def test_20_report_generator_markdown():
    f = Finding(
        finding_id="fnd-rep-2",
        task_id="task-rep",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.HEADER_MISSING,
        title="Missing HTTP Strict Transport Security (HSTS)",
        description="HSTS header missing",
        severity=FindingSeverity.MEDIUM,
        operational_priority=OperationalPriority.P3_MEDIUM_SCHEDULED,
        remediation=FindingRemediation(
            immediate_containment="Add header at proxy",
            permanent_fix="Configure nginx",
            configuration_snippet="add_header Strict-Transport-Security ...",
        ),
    )
    gen = Phase4ReportGenerator(
        target="127.0.0.1",
        task_id="task-rep",
        findings=[f],
        evidence_records=[{"evidence_id": "evi-1", "tool_name": "curl", "operation_name": "headers", "sha256": "abc1234"}],
    )
    md = gen.generate_markdown()
    assert "# REDLOOP Security Assessment & Intelligence Report" in md
    assert "Executive Summary" in md
    assert "Missing HTTP Strict Transport Security (HSTS)" in md
    assert "abc1234" in md


def test_21_report_generator_html():
    f = Finding(
        finding_id="fnd-rep-3",
        task_id="task-rep",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.VULNERABILITY,
        title="Critical RCE",
        description="Remote code execution vulnerability",
        severity=FindingSeverity.CRITICAL,
        operational_priority=OperationalPriority.P1_CRITICAL_IMMEDIATE,
        cisa_kev=True,
    )
    gen = Phase4ReportGenerator("127.0.0.1", "task-rep", [f])
    html_content = gen.generate_html()
    assert "<!DOCTYPE html>" in html_content
    assert "REDLOOP Assessment Report" in html_content
    assert "Critical RCE" in html_content
    assert "P1 - Critical Immediate" in html_content


# =========================================================================
# Part 7: REST API Endpoints Contract
# =========================================================================

@pytest.fixture(scope="module")
def api_client(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("phase4_api")
    db_file = str(tmp_dir / "audit.sqlite")
    from fastapi import FastAPI
    from redloop.workbench import register_workbench_routes
    app = FastAPI()
    register_workbench_routes(app, db_path=db_file, scope_manager=None)
    client = TestClient(app, base_url="http://testserver")
    return client


def test_22_api_list_findings_and_filters(api_client):
    store = FindingStore.get_instance()
    store.clear()
    f1 = Finding(
        finding_id="fnd-api-1",
        task_id="task-api-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 80",
        description="HTTP",
        severity=FindingSeverity.LOW,
        operational_priority=OperationalPriority.P4_LOW_BACKLOG,
    )
    f2 = Finding(
        finding_id="fnd-api-2",
        task_id="task-api-2",
        target="example.com",
        target_type="domain",
        finding_type=FindingType.VULNERABILITY,
        title="SQL Injection",
        description="SQLi vulnerability",
        severity=FindingSeverity.HIGH,
        operational_priority=OperationalPriority.P2_HIGH_URGENT,
    )
    store.add_finding(f1)
    store.add_finding(f2)

    # 1. List all
    res = api_client.get("/api/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2

    # 2. Filter by target
    res_filtered = api_client.get("/api/findings?target=127.0.0.1")
    assert res_filtered.status_code == 200
    assert res_filtered.json()["total"] == 1

    # 3. Filter by severity
    res_sev = api_client.get("/api/findings?severity=HIGH")
    assert res_sev.status_code == 200
    assert res_sev.json()["total"] == 1


def test_23_api_finding_detail_and_validate(api_client):
    store = FindingStore.get_instance()
    f = Finding(
        finding_id="fnd-api-detail",
        task_id="task-1",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.VULNERABILITY,
        title="Test Vuln",
        description="Detail test",
        severity=FindingSeverity.MEDIUM,
        affected_version="2.4.41-4ubuntu3.14",
    )
    store.add_finding(f)

    # GET detail
    res = api_client.get("/api/findings/fnd-api-detail")
    assert res.status_code == 200
    assert res.json()["finding"]["finding_id"] == "fnd-api-detail"

    # POST validate (requires same-origin header)
    res_val = api_client.post(
        "/api/findings/fnd-api-detail/validate",
        headers={"Origin": "http://testserver"},
    )
    assert res_val.status_code == 200
    updated = res_val.json()["finding"]
    assert updated["false_positive_status"]["likelihood"] > 0.5


def test_24_api_intelligence_endpoints(api_client):
    # CVE endpoint
    res_cve = api_client.get("/api/intelligence/cve/CVE-2021-44228")
    assert res_cve.status_code == 200
    cve_data = res_cve.json()["intelligence"]
    assert cve_data["cve_id"] == "CVE-2021-44228"
    assert cve_data["cisa_kev"] is True

    # EPSS endpoint
    res_epss = api_client.get("/api/intelligence/epss/CVE-2021-44228")
    assert res_epss.status_code == 200
    epss_data = res_epss.json()
    assert epss_data["epss_score"] > 0.90


def test_25_api_graph_and_attack_paths(api_client):
    store = FindingStore.get_instance()
    store.clear()
    f = Finding(
        finding_id="fnd-graph-1",
        task_id="task-graph",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.OPEN_PORT,
        title="Open Port 443/tcp",
        description="HTTPS port",
        severity=FindingSeverity.LOW,
        port=443,
        protocol="tcp",
    )
    store.add_finding(f)

    # Graph endpoint
    res_graph = api_client.get("/api/assets/graph?target=127.0.0.1")
    assert res_graph.status_code == 200
    cy = res_graph.json()
    assert "elements" in cy
    assert len(cy["elements"]["nodes"]) >= 1

    # Attack paths endpoint
    res_paths = api_client.get("/api/attack-paths?target=127.0.0.1")
    assert res_paths.status_code == 200
    assert "attack_paths" in res_paths.json()


def test_26_api_analytics_risk_and_reports(api_client):
    store = FindingStore.get_instance()
    store.clear()
    f = Finding(
        finding_id="fnd-risk-api",
        task_id="task-analytics",
        target="127.0.0.1",
        target_type="ip",
        finding_type=FindingType.VULNERABILITY,
        title="Critical Bug",
        description="High risk bug",
        severity=FindingSeverity.CRITICAL,
        operational_priority=OperationalPriority.P1_CRITICAL_IMMEDIATE,
        risk_score=95.0,
        cisa_kev=True,
    )
    store.add_finding(f)

    # Risk analytics
    res_risk = api_client.get("/api/analytics/risk?target=127.0.0.1")
    assert res_risk.status_code == 200
    risk_data = res_risk.json()
    assert risk_data["total_findings"] == 1
    assert risk_data["cisa_kev_exposures"] == 1

    # Report JSON
    res_rep_json = api_client.get("/api/reports/task-analytics?format=json")
    assert res_rep_json.status_code == 200
    assert res_rep_json.json()["report_version"] == "4.0"

    # Report Markdown
    res_rep_md = api_client.get("/api/reports/task-analytics?format=markdown")
    assert res_rep_md.status_code == 200
    assert "# REDLOOP Security Assessment" in res_rep_md.text

    # Report HTML
    res_rep_html = api_client.get("/api/reports/task-analytics?format=html")
    assert res_rep_html.status_code == 200
    assert "<!DOCTYPE html>" in res_rep_html.text
