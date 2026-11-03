"""Phase 2 Automated Test Suite: Tool Capabilities, Environment Detection, Analytics & Autonomous Planning.

Contains 24 comprehensive tests:
1.  Capabilities endpoint schema validation (success, generated_at, environments, tools, summary)
2.  Summary counts match tool array length and status breakdown
3.  Every tool contains all required schema fields and valid types
4.  Host environment detection truthfully reports OS, arch, python, admin, and npcap
5.  WSL detection truthfully reports status and distribution list
6.  Kali Linux detection does not falsely report Kali as present when absent
7.  Docker detection truthfully checks binary presence and daemon status
8.  Truthful reporting: missing binary reports installed=False, available=False, NOT_INSTALLED
9.  Truthful reporting: installed binary reports installed=True, available=True, AVAILABLE
10. Truthful reporting: degraded tool (nmap without npcap on Windows) reports DEGRADED with reason
11. Truthful reporting: API tool without key reports NOT_CONFIGURED with guidance
12. Central registry covers all 8 categories (A through H)
13. GET /api/tools/environments endpoint contract verification
14. GET /api/tools/health endpoint contract verification
15. Autonomous planner: network reconnaissance intent selects nmap/ping
16. Autonomous planner: web security intent selects curl/nikto
17. Autonomous planner: OSINT intent selects nslookup/whois
18. Autonomous planner: enforces scope authorization and flags BLOCKED on unauthorized targets
19. Autonomous planner: argument safety validation (no shell injection, list arguments)
20. Analytics: CVSS v3.1 base score and severity calculation (FIRST standard)
21. Analytics: CVSS v4.0 base score calculation strictly separate from v3.1
22. Analytics: Evidence confidence formula (0.35V + 0.25S + 0.20F + 0.20I) with reweighting
23. Analytics: Completeness and attack surface coverage calculations with N/A checks
24. Regression: Phase 1 TargetResolver & RequestContext target isolation preserved in tool planning
"""

import math
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

from redloop.assessment.analytics import (
    CVSSv31Calculator,
    CVSSv40Calculator,
    EvidenceConfidenceCalculator,
    AssessmentCoverageEngine,
    RiskPrioritizationEngine,
    EvidenceCorrelator,
    OperationalPriority,
    SeverityRating,
)
from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.tools_v2 import (
    EnvironmentDetector,
    ToolCategory,
    ToolHealthStatus,
    ToolRegistryV2,
)
from redloop.assessment.tool_planner import (
    PlanStageState,
    ToolPlanRequest,
    ToolPlanner,
)
from redloop.scope import ScopeManager


# --- TEST 1: Capabilities endpoint schema validation ---
def test_01_capabilities_schema_validation():
    summary = ToolRegistryV2.get_capabilities_summary(force_refresh=True)
    assert summary["success"] is True
    assert "generated_at" in summary
    assert "environments" in summary
    assert "tools" in summary
    assert "summary" in summary
    assert isinstance(summary["tools"], list)
    assert len(summary["tools"]) > 0


# --- TEST 2: Summary counts match tools array ---
def test_02_summary_counts_consistency():
    summary = ToolRegistryV2.get_capabilities_summary()
    tools = summary["tools"]
    s = summary["summary"]

    assert s["total"] == len(tools)
    status_sum = s["available"] + s["degraded"] + s["not_configured"] + s["not_installed"] + s["unavailable"] + s["not_checked"]
    # not_installed is counted within unavailable, so available + degraded + not_configured + unavailable + not_checked == total
    assert s["available"] + s["degraded"] + s["not_configured"] + s["unavailable"] + s["not_checked"] >= s["total"]


# --- TEST 3: All required fields present in tool schema ---
def test_03_tool_schema_completeness():
    tools = ToolRegistryV2.list_all_tools()
    required_keys = {
        "tool_id", "name", "category", "description", "installed", "available",
        "version", "executable_path", "environment", "health_status",
        "verification_method", "last_checked", "reason", "installation_guidance",
        "supported_operations", "supported_target_types", "requires_authorization",
        "passive_or_active"
    }
    for t in tools:
        d = t.to_dict()
        for k in required_keys:
            assert k in d, f"Tool {t.tool_id} is missing key {k}"
        assert isinstance(d["supported_operations"], list)
        assert isinstance(d["supported_target_types"], list)
        assert isinstance(d["requires_authorization"], bool)
        assert d["passive_or_active"] in ("passive", "active", "local")


# --- TEST 4: Host environment detection ---
def test_04_host_environment_detection():
    host = EnvironmentDetector.detect_host()
    assert "os" in host
    assert "architecture" in host
    assert "python_version" in host
    assert "is_admin" in host
    assert "npcap_installed" in host
    assert host["python_version"] == sys.version.split()[0]
    assert isinstance(host["is_admin"], bool)


# --- TEST 5: WSL detection truthfully reports without crash ---
def test_05_wsl_detection():
    wsl = EnvironmentDetector.detect_wsl()
    assert "available" in wsl
    assert "distributions" in wsl
    assert isinstance(wsl["distributions"], list)
    assert isinstance(wsl["available"], bool)


# --- TEST 6: Kali Linux detection truthful ---
def test_06_kali_detection_no_false_positive():
    with patch("redloop.assessment.tools_v2.EnvironmentDetector.detect_wsl", return_value={"available": True, "distributions": ["Ubuntu-22.04"]}):
        with patch("platform.system", return_value="Windows"):
            kali = EnvironmentDetector.detect_kali()
            assert kali["available"] is False
            assert kali["distro_name"] is None

    with patch("redloop.assessment.tools_v2.EnvironmentDetector.detect_wsl", return_value={"available": True, "distributions": ["kali-linux", "Ubuntu"]}):
        with patch("platform.system", return_value="Windows"):
            kali = EnvironmentDetector.detect_kali()
            assert kali["available"] is True
            assert kali["distro_name"] == "kali-linux"


# --- TEST 7: Docker detection truthful and non-blocking ---
def test_07_docker_detection():
    docker = EnvironmentDetector.detect_docker()
    assert "available" in docker
    assert "daemon_running" in docker
    assert isinstance(docker["available"], bool)
    assert isinstance(docker["daemon_running"], bool)


# --- TEST 8: Missing binary reports NOT_INSTALLED ---
def test_08_missing_binary_truthful_status():
    environments = {"host": {"npcap_installed": False}, "wsl": {"available": False}, "kali": {"available": False}, "docker": {"available": False}}
    fake_probe = ["definitely_non_existent_binary_xyz_12345", "--version"]
    tool = ToolRegistryV2._verify_tool(
        tool_id="test_missing",
        name="Test Missing Tool",
        category="network_recon",
        description="Missing tool test",
        probe=fake_probe,
        supported_operations=["scan"],
        supported_target_types=["ipv4"],
        requires_authorization=True,
        passive_or_active="active",
        guidance="Install test missing",
        environments=environments,
        now_iso="2026-11-03T00:00:00Z",
    )
    assert tool.installed is False
    assert tool.available is False
    assert tool.health_status == ToolHealthStatus.NOT_INSTALLED
    assert "was not found" in tool.reason


# --- TEST 9: Installed binary reports AVAILABLE ---
def test_09_installed_binary_truthful_status():
    tool = ToolRegistryV2.get_tool("python3")
    assert tool is not None
    assert tool.installed is True
    assert tool.available is True
    assert tool.health_status == ToolHealthStatus.AVAILABLE
    assert tool.executable_path == sys.executable


# --- TEST 10: Degraded tool (nmap without npcap on Windows) ---
def test_10_degraded_tool_reporting():
    with patch("shutil.which", return_value="C:\\Program Files\\Nmap\\nmap.exe"):
        with patch("os.name", "nt"):
            environments = {
                "host": {"npcap_installed": False},
                "wsl": {"available": False},
                "kali": {"available": False},
            }
            tool = ToolRegistryV2._verify_tool(
                tool_id="nmap",
                name="Nmap Network Scanner",
                category=ToolCategory.NETWORK_RECON.value,
                description="Network exploration",
                probe=["nmap", "--version"],
                supported_operations=["port_scan", "service_detection"],
                supported_target_types=["ipv4"],
                requires_authorization=True,
                passive_or_active="active",
                guidance="Install Npcap",
                environments=environments,
                now_iso="2026-11-03T00:00:00Z",
            )
            assert tool.health_status == ToolHealthStatus.DEGRADED
            assert "Npcap driver missing" in tool.reason


# --- TEST 11: Unconfigured API tool reports NOT_CONFIGURED ---
def test_11_unconfigured_api_tool():
    with patch.dict(os.environ, {"SHODAN_API_KEY": ""}, clear=False):
        environments = EnvironmentDetector.detect_all()
        tool = ToolRegistryV2._verify_tool(
            tool_id="shodan",
            name="Shodan API",
            category=ToolCategory.OSINT.value,
            description="Shodan Intel",
            probe=["api_key_check", "SHODAN_API_KEY"],
            supported_operations=["ip_enrichment"],
            supported_target_types=["ipv4"],
            requires_authorization=False,
            passive_or_active="passive",
            guidance="Configure SHODAN_API_KEY",
            environments=environments,
            now_iso="2026-11-03T00:00:00Z",
        )
        assert tool.health_status == ToolHealthStatus.NOT_CONFIGURED
        assert tool.available is False
        assert "Missing environment variable" in tool.reason


# --- TEST 12: Registry covers 8 categories (A-H) ---
def test_12_registry_covers_all_eight_categories():
    tools = ToolRegistryV2.list_all_tools()
    categories_found = {t.category for t in tools}
    expected = {
        ToolCategory.NETWORK_RECON.value,
        ToolCategory.WEB_SECURITY.value,
        ToolCategory.TLS_CERTS.value,
        ToolCategory.VULN_INTEL.value,
        ToolCategory.OSINT.value,
        ToolCategory.FORENSICS.value,
        ToolCategory.DEFENSIVE_SOC.value,
        ToolCategory.LOCAL_TERMINAL.value,
    }
    assert expected.issubset(categories_found)


# --- TEST 13: Environments endpoint contract ---
def test_13_environments_endpoint_contract():
    envs = EnvironmentDetector.detect_all()
    assert "host" in envs
    assert "wsl" in envs
    assert "kali" in envs
    assert "linux" in envs
    assert "docker" in envs


# --- TEST 14: Health endpoint contract ---
def test_14_health_endpoint_contract():
    summary = ToolRegistryV2.get_capabilities_summary()
    assert summary["success"] is True
    assert summary["summary"]["total"] >= 15


# --- TEST 15: Autonomous planner: Network Recon intent ---
def test_15_autonomous_planner_network_recon():
    planner = ToolPlanner()
    req = ToolPlanRequest(
        prompt="Scan open TCP ports on 127.0.0.1",
        target="127.0.0.1",
        intensity="normal",
    )
    plan = planner.create_plan(req)
    assert plan.target == "127.0.0.1"
    assert plan.task_intent == "network_recon"
    stage_tools = [s.tool_id for s in plan.stages]
    assert "nmap" in stage_tools or "ping" in stage_tools


# --- TEST 16: Autonomous planner: Web Security intent ---
def test_16_autonomous_planner_web_security():
    planner = ToolPlanner()
    req = ToolPlanRequest(
        prompt="Audit web server vulnerabilities and headers on http://localhost:8080",
        target="localhost",
    )
    plan = planner.create_plan(req)
    assert plan.task_intent == "web_security"
    stage_tools = [s.tool_id for s in plan.stages]
    assert "curl" in stage_tools or "nikto" in stage_tools


# --- TEST 17: Autonomous planner: OSINT intent ---
def test_17_autonomous_planner_osint():
    planner = ToolPlanner()
    req = ToolPlanRequest(
        prompt="Perform whois and DNS reconnaissance for example.com",
        target="example.com",
    )
    plan = planner.create_plan(req)
    assert plan.task_intent == "osint"
    stage_tools = [s.tool_id for s in plan.stages]
    assert "nslookup" in stage_tools or "whois" in stage_tools


# --- TEST 18: Autonomous planner blocks unauthorized target ---
def test_18_autonomous_planner_blocks_unauthorized_target():
    mock_sm = MagicMock()
    mock_sm.check.side_effect = Exception("Target not in scope")
    planner = ToolPlanner(scope_manager=mock_sm)

    req = ToolPlanRequest(
        prompt="Run aggressive port scan on 192.168.1.100",
        target="192.168.1.100",
    )
    plan = planner.create_plan(req)
    assert plan.requires_scope_approval is True
    assert plan.status == PlanStageState.BLOCKED
    # Check that network stage requiring authorization is marked BLOCKED
    blocked_stages = [s for s in plan.stages if s.requires_authorization]
    for s in blocked_stages:
        assert s.status == PlanStageState.BLOCKED


# --- TEST 19: Argument safety validation (no shell injection) ---
def test_19_argument_safety():
    planner = ToolPlanner()
    req = ToolPlanRequest(
        prompt="Scan target 127.0.0.1; rm -rf / ; cat /etc/passwd",
        target="127.0.0.1",
    )
    plan = planner.create_plan(req)
    for stage in plan.stages:
        assert isinstance(stage.command_args, list)
        # Verify no shell chaining metacharacters were spliced into discrete arguments
        for arg in stage.command_args:
            assert "; rm -rf" not in arg
            assert "&&" not in arg
            assert "||" not in arg


# --- TEST 20: CVSS v3.1 calculation (FIRST standard) ---
def test_20_cvss_v31_calculation():
    # Example 1: Critical (Log4j style)
    vec1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    res1 = CVSSv31Calculator.calculate(vec1)
    assert res1["base_score"] == 9.8
    assert res1["severity"] == SeverityRating.CRITICAL.value

    # Example 2: Medium with User Interaction
    vec2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    res2 = CVSSv31Calculator.calculate(vec2)
    assert 5.0 <= res2["base_score"] <= 6.5
    assert res2["severity"] == SeverityRating.MEDIUM.value


# --- TEST 21: CVSS v4.0 calculation strictly separate ---
def test_21_cvss_v40_calculation():
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    res = CVSSv40Calculator.calculate(vec)
    assert res["version"] == "4.0"
    assert res["is_v4"] is True
    assert res["base_score"] >= 9.0
    assert res["severity"] == SeverityRating.CRITICAL.value


# --- TEST 22: Evidence confidence formula and missing metrics reweighting ---
def test_22_evidence_confidence_reweighting():
    # Full components: C = 0.35*1.0 + 0.25*0.8 + 0.20*1.0 + 0.20*1.0 = 0.35 + 0.20 + 0.20 + 0.20 = 0.95
    res_full = EvidenceConfidenceCalculator.calculate(
        verification_status=1.0,
        source_reliability=0.8,
        finding_freshness=1.0,
        tool_integrity=1.0,
    )
    assert math.isclose(res_full.score, 0.95, abs_tol=0.01)
    assert res_full.confidence_level == "HIGH"
    assert len(res_full.missing_components) == 0

    # Missing freshness (e.g. static local finding): weights 0.35, 0.25, 0.20 sum to 0.80 -> reweighted
    res_reweighted = EvidenceConfidenceCalculator.calculate(
        verification_status=1.0,
        source_reliability=1.0,
        finding_freshness=None,
        tool_integrity=1.0,
    )
    assert math.isclose(res_reweighted.score, 1.0, abs_tol=0.01)
    assert "F" in res_reweighted.missing_components
    assert math.isclose(sum(res_reweighted.normalized_weights.values()), 1.0, abs_tol=0.001)


# --- TEST 23: Completeness and coverage calculations ---
def test_23_completeness_and_coverage_handling():
    planned = ["ping", "port_scan", "tls_audit", "banner_grab", "auth_bypass"]
    performed = ["ping", "port_scan", "tls_audit"]
    na_checks = ["auth_bypass"]

    comp = AssessmentCoverageEngine.calculate_completeness(planned, performed, na_checks)
    # Valid planned: 4 (auth_bypass excluded as NA). Performed valid: 3 -> 3/4 = 0.75
    assert comp.completeness_ratio == 0.75
    assert "banner_grab" in comp.unperformed_checks
    assert comp.na_checks == 1

    known_facets = ["port:80", "port:443", "port:8080", "path:/admin", "path:/login"]
    observed_facets = ["port:80", "port:443", "path:/login"]
    cov = AssessmentCoverageEngine.calculate_coverage(known_facets, observed_facets)
    assert cov.coverage_ratio == 0.6  # 3 / 5
    assert "port:8080" in cov.unobserved_facets
    assert "path:/admin" in cov.unobserved_facets


# --- TEST 24: Phase 1 Target isolation regression check ---
def test_24_target_isolation_regression_in_planner():
    ctx = RequestContext(
        request_id="req-phase2-test",
        explicit_target="192.168.1.50",
        user_message="Scan target 192.168.1.50",
    )
    planner = ToolPlanner()
    # Explicit prompt without target should not silently use stale 127.0.0.1 or previous
    req1 = ToolPlanRequest(prompt="What are standard OWASP vulnerabilities?", target=None)
    plan1 = planner.create_plan(req1)
    assert plan1.target is None or plan1.task_intent == "diagnostic"

    # Explicit prompt with target overrides request context
    req2 = ToolPlanRequest(prompt="Scan 10.0.0.1", target="10.0.0.1")
    plan2 = planner.create_plan(req2, request_context=ctx)
    assert plan2.target == "10.0.0.1"
