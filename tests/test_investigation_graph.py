"""Unit tests for Dual-Graph, Remediation Verification, Replay Diff, and Model Evaluator."""

import pytest
from redloop.investigation_graph import (
    GraphNode,
    InvestigationGraph,
    InvestigationReplay,
    MultiModelEvaluator,
    NodeType,
    ProvenanceType,
    RemediationVerifier,
)


def test_investigation_graph_dual_nodes_and_cytoscape(tmp_path):
    graph = InvestigationGraph(investigation_id="inv_test_001", storage_dir=str(tmp_path))

    # Add Asset Node
    host_node = graph.add_node(
        node_id="asset_127_0_0_1",
        node_type=NodeType.ASSET,
        label="127.0.0.1",
        provenance=ProvenanceType.DIRECTLY_OBSERVED,
    )
    # Add Finding Node
    finding_node = graph.add_node(
        node_id="find_missing_csp",
        node_type=NodeType.FINDING,
        label="Missing Content-Security-Policy",
        provenance=ProvenanceType.INFERRED_FROM_EVIDENCE,
        properties={"severity": "MEDIUM", "status": "OPEN"},
    )
    # Add Edge
    graph.add_edge(source_id=host_node.id, target_id=finding_node.id, relation="EXPOSES_VULNERABILITY")

    elements = graph.to_cytoscape_elements()
    assert len(elements) == 3  # 2 nodes + 1 edge
    assert any(el["data"]["id"] == "asset_127_0_0_1" for el in elements)
    assert any(el["data"]["id"] == "find_missing_csp" for el in elements)


def test_remediation_verification(tmp_path):
    graph = InvestigationGraph(investigation_id="inv_test_002", storage_dir=str(tmp_path))
    finding = graph.add_node(
        node_id="find_port_8080",
        node_type=NodeType.FINDING,
        label="Unauthenticated Admin Port 8080",
        provenance=ProvenanceType.DIRECTLY_OBSERVED,
        properties={"status": "OPEN"},
    )

    # 1. Test when vulnerability still exists
    mock_fail = lambda: {"is_vulnerable": True, "evidence": "Port 8080 is still open and listening."}
    res_fail = RemediationVerifier.verify_remediation(graph, finding.id, mock_fail)
    assert res_fail["status"] == "REMEDIATION_FAILED_STILL_VULNERABLE"

    # 2. Test when vulnerability is resolved
    mock_pass = lambda: {"is_vulnerable": False, "evidence": "Connection to port 8080 refused; socket closed."}
    res_pass = RemediationVerifier.verify_remediation(graph, finding.id, mock_pass)
    assert res_pass["status"] == "REMEDIATED_AND_VERIFIED"
    assert finding.provenance == ProvenanceType.REMEDIATED_AND_RETESTED


def test_investigation_replay_diff(tmp_path):
    base_g = InvestigationGraph(investigation_id="base_run", storage_dir=str(tmp_path))
    base_g.add_node("f1", NodeType.FINDING, "Missing HSTS", ProvenanceType.DIRECTLY_OBSERVED)
    base_g.add_node("f2", NodeType.FINDING, "Exposed .env file", ProvenanceType.DIRECTLY_OBSERVED)

    replayed_g = InvestigationGraph(investigation_id="replay_run", storage_dir=str(tmp_path))
    replayed_g.add_node("f1", NodeType.FINDING, "Missing HSTS", ProvenanceType.DIRECTLY_OBSERVED)
    # f2 was resolved, and new finding f3 was discovered
    replayed_g.add_node("f3", NodeType.FINDING, "Outdated OpenSSL version", ProvenanceType.DIRECTLY_OBSERVED)

    diff = InvestigationReplay.diff_investigations(base_g, replayed_g)
    assert diff["summary"]["resolved_count"] == 1
    assert diff["resolved_findings"][0]["label"] == "Exposed .env file"
    assert diff["summary"]["new_findings_count"] == 1
    assert diff["new_findings"][0]["label"] == "Outdated OpenSSL version"
    assert diff["summary"]["persistent_count"] == 1


class _StubGateway:
    def __init__(self, success: bool = True):
        self.success = success

    def discover_models(self, provider_id: str):
        return ["llama-3.3-70b-versatile"]

    def test_provider(self, provider_id: str):
        if self.success:
            return {
                "success": True,
                "status": "INFERENCE_READY",
                "latency_ms": 12.5,
            }
        return {
            "success": False,
            "status": "AUTH_FAILED",
            "error": "API key is not configured.",
        }


def test_multi_model_evaluator_reports_only_connectivity_probe():
    res = MultiModelEvaluator.evaluate_provider(
        "groq", "llama-3.3-70b-versatile", gateway=_StubGateway(True)
    )
    assert res["provider_id"] == "groq"
    assert res["evaluation_mode"] == "CONNECTIVITY_PROBE_ONLY"
    assert res["benchmark_suite"] == "NOT_EXECUTED"
    assert res["tests_run"] == 1
    assert res["tests_passed"] == 1
    assert res["reasoning_verified"] is False
    assert res["scope_enforcement_verified"] is False
    assert res["model_declared_supported"] is True

    failed = MultiModelEvaluator.evaluate_provider(
        "groq", "llama-3.3-70b-versatile", gateway=_StubGateway(False)
    )
    assert failed["tests_passed"] == 0
    assert failed["provider_status"] == "AUTH_FAILED"
    assert failed["details"][0]["passed"] is False


def test_remediation_inconclusive_does_not_claim_success(tmp_path):
    graph = InvestigationGraph(investigation_id="inv_inconclusive", storage_dir=str(tmp_path))
    finding = graph.add_node(
        node_id="find_timeout",
        node_type=NodeType.FINDING,
        label="Timed out probe",
        properties={"status": "OPEN"},
    )
    res = RemediationVerifier.verify_remediation(
        graph,
        finding.id,
        lambda: {"is_vulnerable": None, "evidence": "connect timed out"},
    )
    assert res["success"] is False
    assert res["status"] == "REMEDIATION_NOT_VERIFIED"
    assert finding.provenance != ProvenanceType.REMEDIATED_AND_RETESTED
    assert finding.properties["status"] == "REMEDIATION_NOT_VERIFIED"


def test_corrupt_graph_is_not_silently_overwritten(tmp_path):
    graph = InvestigationGraph(investigation_id="inv_corrupt", storage_dir=str(tmp_path))
    graph.add_node("asset-1", NodeType.ASSET, "Asset", ProvenanceType.DIRECTLY_OBSERVED)
    original = graph.graph_file.read_text(encoding="utf-8")
    graph.graph_file.write_text("{not valid json", encoding="utf-8")

    broken = InvestigationGraph(investigation_id="inv_corrupt", storage_dir=str(tmp_path))
    assert broken.load_error is not None
    with pytest.raises(RuntimeError):
        broken.save()
    assert graph.graph_file.read_text(encoding="utf-8") == "{not valid json"

    broken.clear()
    assert broken.load_error is None
    reloaded = InvestigationGraph(investigation_id="inv_corrupt", storage_dir=str(tmp_path))
    assert reloaded.nodes == {}
    assert original  # original capture is retained for diagnostics
