"""Regression tests for OSINT classification, provenance, confidence, cache, and evidence."""

from __future__ import annotations

import ipaddress

import pytest

from redloop.investigation_graph import InvestigationGraph, NodeType, ProvenanceType
from redloop.osint_engine import (
    OSINTEngine,
    classify_ip_address,
    populate_investigation_graph_from_osint,
)


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, url: str = "https://rdap.arin.net/registry/ip/8.8.8.8"):
        self.status_code = status_code
        self._payload = payload or {}
        self.url = url

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def get(self, url):
        self.calls += 1
        if not self._responses:
            return _FakeResponse(500)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _rdap_payload() -> dict:
    return {
        "name": "LVLT-GOGL-8-8-8",
        "handle": "NET-8-8-8-0-1",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "type": "DIRECT ALLOCATION",
        "country": "US",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
            }
        ],
    }


def _fake_engine(monkeypatch, responses=None, ttl=300.0) -> OSINTEngine:
    monkeypatch.setattr(
        "redloop.threat_intel.get_threat_intel_engine",
        lambda: (_ for _ in ()).throw(RuntimeError("no provider configured")),
    )
    return OSINTEngine(http_client=_FakeClient(responses or [_FakeResponse(200, _rdap_payload())]), cache_ttl_seconds=ttl)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", "GLOBAL_PUBLIC"),
        ("127.0.0.1", "LOOPBACK"),
        ("192.168.1.1", "PRIVATE"),
        ("169.254.1.1", "LINK_LOCAL"),
        ("224.0.0.1", "MULTICAST"),
        ("192.0.2.1", "DOCUMENTATION"),
        ("999.999.999.999", "INVALID"),
    ],
)
def test_ip_classification_table(value, expected):
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        assert expected == "INVALID"
        return
    assert classify_ip_address(parsed) == expected


def test_loopback_is_local_only_and_honest(monkeypatch):
    engine = _fake_engine(monkeypatch)
    res = engine.investigate_ip("127.0.0.1")

    assert res.classification == "LOOPBACK"
    assert res.reverse_dns["status"] == "NOT_QUERIED"
    assert res.reverse_dns["hostname"] is None
    assert not any(e.get("type") == "domain" for e in res.related_entities)
    assert res.confidence >= 0.8
    assert res.confidence_type == "HEURISTIC"
    assert "independent_corroboration" in res.not_applicable_factors
    assert res.cache_status == "LIVE"
    assert res.evidence_integrity_valid is True


def test_invalid_and_empty_are_failed_with_zero_confidence(monkeypatch):
    engine = _fake_engine(monkeypatch)
    for value in ("", "999.999.999.999", "not-an-ip"):
        res = engine.investigate_ip(value)
        assert res.status.value == "FAILED"
        assert res.confidence == 0.0
        assert res.actual_finding


def test_provenance_is_measured_not_fabricated(monkeypatch):
    engine = _fake_engine(monkeypatch)
    res = engine.investigate_ip("8.8.8.8")

    assert 0.0 < res.provenance_completeness < 1.0
    assert res.field_provenance["registry"]["status"] == "PRESENT"
    assert res.field_provenance["asn"]["status"] in ("PRESENT", "MISSING")
    assert res.field_provenance["geo"]["status"] == "MISSING"
    assert all(
        item["status"] != "PRESENT" or item.get("reason") is None
        for item in res.field_provenance.values()
    )


def test_evidence_hash_detects_mutation(monkeypatch):
    engine = _fake_engine(monkeypatch)
    res = engine.investigate_ip("8.8.8.8")
    assert res.verify_evidence_integrity()["valid"] is True

    res.findings.append({"property": "injected", "value": "tampered"})
    integrity = res.verify_evidence_integrity()
    assert integrity["valid"] is False
    assert integrity["expected_hash"] != integrity["actual_hash"]


def test_cache_is_labeled_and_stale_fallback_is_explicit(monkeypatch):
    engine = _fake_engine(
        monkeypatch,
        responses=[_FakeResponse(200, _rdap_payload()), _FakeResponse(500)],
        ttl=0.0,
    )
    live = engine.investigate_ip("8.8.8.8")
    assert live.cache_status == "LIVE"

    stale = engine.investigate_ip("8.8.8.8")
    assert stale.cache_status == "STALE"
    assert stale.cached is True
    assert stale.cache_fallback_reason
    assert any("cache" in item.lower() for item in stale.limitations)


def test_failed_results_are_not_cached(monkeypatch):
    engine = _fake_engine(monkeypatch)
    engine.investigate_ip("999.999.999.999")
    assert engine._cache.get("ip:999.999.999.999") is None


def test_osint_api_and_ui_expose_real_fields(tmp_path):
    from fastapi.testclient import TestClient
    from redloop.dashboard import create_app

    client = TestClient(create_app(str(tmp_path / "audit.db")))
    payload = client.post("/api/osint/ip", json={"indicator": "127.0.0.1", "target": "127.0.0.1"}).json()

    assert payload["classification"] == "LOOPBACK"
    assert payload["cache_status"] in {"LIVE", "CACHED", "STALE"}
    assert payload["confidence_type"] == "HEURISTIC"
    assert payload["field_provenance"]["reverse_dns"]["status"] == "NOT_APPLICABLE"
    assert payload["evidence_integrity_valid"] is True
    assert payload["provenance_completeness"] is not None

    html = client.get("/").text
    assert "STALE CACHE" in html
    assert "SHA-256 VERIFIED" in html
    assert "d.provenance_completeness || 1.0" not in html


def test_graph_carries_verification_and_provenance(monkeypatch, tmp_path):
    engine = _fake_engine(monkeypatch)
    res = engine.investigate_ip("8.8.8.8")
    graph = InvestigationGraph(tmp_path / "inv-test.graph")
    populate_investigation_graph_from_osint(graph, res)

    asset_id = f"asset-ip-{res.normalized_value.replace('/', '_').replace(':', '_')}"
    asset = graph.nodes[asset_id]
    assert asset.provenance == ProvenanceType.EXTERNALLY_ENRICHED
    assert asset.properties["confidence_type"] == "HEURISTIC"
    assert asset.properties["field_provenance"]["asn"]["status"] in ("PRESENT", "MISSING")

    evidence_id = f"evi-{res.evidence_id}"
    evidence = graph.nodes[evidence_id]
    assert evidence.type == NodeType.EVIDENCE
    assert evidence.properties["evidence_integrity"] is True
    assert evidence.properties["evidence_hash"] == res.evidence_hash
