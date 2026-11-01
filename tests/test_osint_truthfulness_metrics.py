import ipaddress
import time

import pytest

from redloop.investigation_graph import InvestigationGraph
from redloop.osint_engine import (
    EVIDENCE_VERSION_MISMATCH,
    IP_CLASSIFICATIONS,
    OSINTCache,
    OSINTEngine,
    OSINTResult,
    OSINTVerificationState,
    classify_ip_address,
    populate_investigation_graph_from_osint,
)


class _ExplodingClient:
    def get(self, *args, **kwargs):
        raise AssertionError("External HTTP must not be called for non-public addresses")


def test_ip_classification_has_reserved_and_unspecified_categories():
    assert classify_ip_address(ipaddress.ip_address("0.0.0.0")) == "UNSPECIFIED"
    assert classify_ip_address(ipaddress.ip_address("::")) == "UNSPECIFIED"
    assert classify_ip_address(ipaddress.ip_address("0.0.0.1")) == "RESERVED"
    assert classify_ip_address(ipaddress.ip_address("240.0.0.1")) == "RESERVED"
    assert classify_ip_address(ipaddress.ip_address("255.255.255.255")) == "RESERVED"
    assert classify_ip_address(ipaddress.ip_address("198.18.0.1")) == "RESERVED"
    assert classify_ip_address(ipaddress.ip_address("192.0.0.10")) == "RESERVED"
    assert classify_ip_address(ipaddress.ip_address("::ffff:8.8.8.8")) == "GLOBAL_PUBLIC"
    assert {"RESERVED", "UNSPECIFIED"}.issubset(IP_CLASSIFICATIONS)


def test_multicast_is_not_treated_as_externally_routable():
    engine = OSINTEngine(http_client=_ExplodingClient())
    result = engine.investigate_ip("224.0.0.1")
    assert result.classification == "MULTICAST"
    assert result.registry_status == "NOT_APPLICABLE"
    assert result.network_status == "NOT_APPLICABLE"
    assert result.asn_status == "NOT_APPLICABLE"
    assert result.reverse_dns["status"] == "NOT_QUERIED"
    classification = next(
        item for item in result.findings if item.get("property") == "classification"
    )
    assert classification["is_global"] is True
    assert classification["scope"] == "MULTICAST"


def test_result_without_observation_does_not_fabricate_evidence_confidence():
    result = OSINTResult(
        indicator="",
        query_type="ip",
        normalized_value="",
        actual_finding="IP address is required.",
        confidence=0.0,
    )
    assert result.confidence_evidence["status"] == "INSUFFICIENT_EVIDENCE"
    assert result.confidence_evidence["score"] is None
    assert result.confidence_evidence_score is None


def test_result_exposes_evidence_confidence_agreement_and_freshness():
    result = OSINTResult(
        indicator="127.0.0.1",
        query_type="ip",
        normalized_value="127.0.0.1",
        actual_finding="loopback",
        classification="LOOPBACK",
        confidence=0.8,
        status=OSINTVerificationState.OBSERVED,
    )
    assert result.confidence_methodology == "HEURISTIC_CONFIDENCE"
    assert result.confidence_evidence["label"] == "HEURISTIC_CONFIDENCE"
    assert result.confidence_evidence["calibration_status"] == "NOT_CALIBRATED"
    assert result.confidence_evidence_score is not None
    assert result.source_agreement["status"] in {"SINGLE_SOURCE", "CORROBORATED"}
    assert result.freshness_decay["half_life_seconds"] > 0
    assert 0.0 <= result.freshness_decay["score"] <= 1.0
    assert result.cache_state == "LIVE"
    assert result.provenance_policy["status"] in {"COMPLETE", "INCOMPLETE"}


def test_unsupported_evidence_hash_version_is_rejected():
    result = OSINTResult(
        indicator="127.0.0.1",
        query_type="ip",
        normalized_value="127.0.0.1",
        actual_finding="loopback",
        classification="LOOPBACK",
        evidence_hash_version="sha256-canonical-v999",
    )
    integrity = result.verify_evidence_integrity()
    assert integrity["valid"] is False
    assert integrity["status"] == EVIDENCE_VERSION_MISMATCH
    assert integrity["expected_hash"] is None
    assert result.evidence_integrity_valid is False
    assert result.status == OSINTVerificationState.FAILED
    assert result.confidence_evidence["status"] == "INSUFFICIENT_EVIDENCE"
    assert result.confidence_evidence["reason"] == "EVIDENCE_INTEGRITY_INVALID"
    assert result.confidence_evidence_score is None


def test_cache_exposes_canonical_states_and_keeps_legacy_status():
    cache = OSINTCache(default_ttl_seconds=60.0, stale_ttl_seconds=120.0)
    result = OSINTResult(
        indicator="127.0.0.1",
        query_type="ip",
        normalized_value="127.0.0.1",
        actual_finding="loopback",
        classification="LOOPBACK",
    )
    assert cache.set("ip:127.0.0.1", result) is True
    assert cache.state_for("ip:127.0.0.1") == "CACHED_FRESH"
    fresh = cache.get("ip:127.0.0.1")
    assert fresh is not None
    assert fresh.cache_status == "CACHED"
    assert fresh.cache_state == "CACHED_FRESH"
    assert fresh.freshness["decay"]["half_life_seconds"] > 0
    assert cache.state_for("ip:missing") == "CACHE_MISS"

    stale_cache = OSINTCache(default_ttl_seconds=0.0, stale_ttl_seconds=60.0)
    stale_cache.set("ip:8.8.8.8", result)
    time.sleep(0.01)
    assert stale_cache.get("ip:8.8.8.8") is None
    stale = stale_cache.get_stale("ip:8.8.8.8")
    assert stale is not None
    assert stale.cache_status == "STALE"
    assert stale.cache_state == "CACHED_STALE"
    assert stale.cache_fallback_reason is not None

    expired_cache = OSINTCache(default_ttl_seconds=0.0, stale_ttl_seconds=0.0)
    expired_cache.set("ip:1.1.1.1", result)
    time.sleep(0.01)
    assert expired_cache.state_for("ip:1.1.1.1") == "EXPIRED"


def test_related_entities_and_graph_edges_carry_source_and_evidence(tmp_path):
    result = OSINTResult(
        indicator="example.test",
        query_type="domain",
        normalized_value="example.test",
        actual_finding="domain observation",
        confidence=0.9,
        related_entities=[
            {"type": "ip", "value": "203.0.113.10", "relation": "RESOLVES_TO"},
        ],
    )
    entity = result.related_entities[0]
    assert entity["source"]
    assert entity["method"]
    assert entity["evidence_reference"] == result.evidence_id
    assert entity["timestamp"] == result.observation_timestamp
    assert entity["verification_state"]

    graph = InvestigationGraph(tmp_path / "truthful.graph")
    populate_investigation_graph_from_osint(graph, result)
    edge_elements = [
        element["data"]
        for element in graph.to_cytoscape()
        if element["data"].get("relation") not in {None, "PRODUCED_BY"}
    ]
    assert edge_elements
    for edge in edge_elements:
        assert edge["source"]
        assert edge["evidence_reference"]
        assert edge["method"]
        assert edge["timestamp"]
