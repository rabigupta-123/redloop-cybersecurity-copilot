"""Tests for PentAGI adaptations: ExploitSimulator, ShodanEngine, and CTFCodec."""

import pytest
from redloop.assessment.exploit_simulator import ExploitSimulator
from redloop.assessment.shodan_engine import ShodanEngine
from redloop.assessment.ctf_toolkit import CTFCodec
from redloop.assessment.models import AttackSurfaceGraph
from redloop.audit import AuditLogger


def test_exploit_simulator_records_audit_and_evidence(tmp_path):
    audit_db = tmp_path / "test_audit.db"
    audit = AuditLogger(audit_db)
    sim = ExploitSimulator(audit=audit, scope_guard=None)

    res = sim.simulate(target="127.0.0.1", service="http", port=8080)
    assert res.simulation_id.startswith("sim-")
    assert res.mitre_technique == "T1059.004"
    assert len(res.steps) == 4
    assert len(res.evidence) == 1
    assert res.finding is not None
    assert res.finding.id.startswith("RL-SIM-")

    # Verify audit ledger
    chain_info = audit.verify_chain()
    assert chain_info["valid"] is True
    assert chain_info["total_events"] == 1


def test_exploit_simulator_updates_graph(tmp_path):
    audit = AuditLogger(tmp_path / "audit.db")
    sim = ExploitSimulator(audit=audit, scope_guard=None)
    res = sim.simulate(target="127.0.0.1", service="ssh", port=22)

    graph = AttackSurfaceGraph()
    sim.update_graph_with_simulation(graph, res)
    node_ids = [n.id for n in graph.nodes]
    assert f"exploit:{res.simulation_id}" in node_ids
    assert f"technique:{res.mitre_technique}" in node_ids


def test_shodan_engine_loopback_handling(tmp_path):
    audit = AuditLogger(tmp_path / "audit.db")
    engine = ShodanEngine(audit=audit, scope_guard=None, api_key="test_dummy_key")
    res = engine.query_host("127.0.0.1")
    assert res["success"] is True
    data = res["data"]
    assert data["ip"] == "127.0.0.1"
    assert "Loopback Security Boundary" in data["org"]


def test_ctf_codec_base64_and_flags():
    encoded = "flag{cyber_sentinel_2026}"
    import base64
    b64 = base64.b64encode(encoded.encode()).decode()
    res = CTFCodec.decode(b64)
    assert encoded in res.output_text
    assert "flag{cyber_sentinel_2026}" in res.flag_matches


def test_ctf_codec_caesar_frequency():
    plain = "attackatdawn"
    # Shift by 3: dwwdfndwgdzq
    shifted = "".join(chr((ord(c) - ord('a') + 3) % 26 + ord('a')) for c in plain)
    res = CTFCodec.decode(shifted)
    # Check that Caesar or ROT candidate exists
    candidates = [c["value"] for c in res.all_candidates]
    assert plain in candidates


def test_ctf_codec_hash_identification():
    md5_hash = "5d41402abc4b2a76b9719d911017c592"
    types = CTFCodec.identify_hash(md5_hash)
    assert "MD5" in types
    sha256_hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    types_256 = CTFCodec.identify_hash(sha256_hash)
    assert "SHA-256" in types_256
