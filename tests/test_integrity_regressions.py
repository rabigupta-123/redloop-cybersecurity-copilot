"""Regression tests for audit concurrency, evidence reload integrity, and remediation retests."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

from redloop.assessment.engine import AssessmentStore
from redloop.assessment.models import AssessmentState, Evidence, Finding, Severity
from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from redloop.investigation_graph import (
    InvestigationGraph,
    NodeType,
    ProvenanceType,
    RemediationVerifier,
)
from redloop.scope import ScopeManager, sign_scope


def test_concurrent_audit_writes_do_not_fork_chain(tmp_path):
    audit = AuditLogger(db_path=tmp_path / "audit.db")

    def writer(worker: int) -> None:
        for i in range(4):
            audit.log("127.0.0.1", "scan", f"worker-{worker}", "success", {"i": i})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(writer, range(8)))

    verification = audit.verify_chain()
    assert verification["valid"] is True, verification
    assert verification["total_events"] == 32
    rows = audit.fetch(limit=100)
    assert len(rows) == 32


def test_assessment_load_detects_tampered_evidence(tmp_path):
    store = AssessmentStore(db_path=tmp_path / "assessments.sqlite")
    evidence = Evidence(target="127.0.0.1", response_excerpt="original body")
    state = AssessmentState(
        target="127.0.0.1",
        findings=[
            Finding(
                title="Tampered evidence",
                category="web",
                severity=Severity.LOW,
                asset="127.0.0.1",
                target="127.0.0.1",
                description="seed",
                evidence=[evidence],
            )
        ],
    )
    store.save(state)

    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute(
            "SELECT state_json FROM assessments WHERE id = ?", (state.id,)
        ).fetchone()
        tampered = row[0].replace("original body", "tampered body")
        assert tampered != row[0]
        conn.execute(
            "UPDATE assessments SET state_json = ? WHERE id = ?", (tampered, state.id)
        )
        conn.commit()

    loaded = store.load(state.id)
    assert loaded is not None
    errors = [e for e in loaded.errors if e.get("error_type") == "evidence_integrity_failed"]
    assert errors, loaded.errors
    assert errors[0]["evidence_id"] == evidence.id


def _scope_manager(tmp_path, port: int) -> ScopeManager:
    today = date.today()
    data = {
        "version": 1,
        "id": "remediation-test",
        "authorized_by": "sec-ops",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": str(today - timedelta(days=1)),
                "authorized_until": str(today + timedelta(days=30)),
                "allowed_actions": ["recon", "scan"],
                "ports": [port],
            }
        ],
    }
    secret = "remediation-test-secret"
    data["signature"] = sign_scope(data, secret)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    return ScopeManager(scope_file, secret)


def test_verify_remediation_endpoint_never_trusts_client_result(tmp_path, monkeypatch):
    monkeypatch.setenv("REDLOOP_DATA_DIR", str(tmp_path))
    port = 45678
    scope_manager = _scope_manager(tmp_path, port)
    graph = InvestigationGraph(investigation_id="inv-endpoint")
    graph.add_node(
        "find-open-port",
        NodeType.FINDING,
        "Open port",
        ProvenanceType.DIRECTLY_OBSERVED,
        properties={"target": "127.0.0.1", "port": port},
    )
    graph.add_node(
        "find-no-metadata",
        NodeType.FINDING,
        "No retest metadata",
        ProvenanceType.DIRECTLY_OBSERVED,
        properties={},
    )

    monkeypatch.setattr(
        RemediationVerifier,
        "build_port_probe",
        staticmethod(
            lambda target, port, timeout=3.0: (
                lambda: {"is_vulnerable": False, "evidence": "probe: connection refused"}
            )
        ),
    )

    app = create_app(str(tmp_path / "audit.db"), scope_manager=scope_manager)
    client = TestClient(app, base_url="http://127.0.0.1")

    forged = client.post(
        "/api/investigations/inv-endpoint/verify-remediation",
        json={"finding_id": "find-open-port", "is_vulnerable": False, "evidence": "trust me"},
    )
    assert forged.status_code == 422

    res = client.post(
        "/api/investigations/inv-endpoint/verify-remediation",
        json={"finding_id": "find-open-port"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "REMEDIATED_AND_VERIFIED"
    assert body["evidence_hash"]

    missing = client.post(
        "/api/investigations/inv-endpoint/verify-remediation",
        json={"finding_id": "find-no-metadata"},
    )
    assert missing.status_code == 422

    reloaded = InvestigationGraph(investigation_id="inv-endpoint")
    assert reloaded.nodes["find-open-port"].properties["status"] == "REMEDIATED_AND_VERIFIED"
    evidence = json.loads(reloaded.graph_file.read_text(encoding="utf-8"))
    assert any(n["type"] == "EVIDENCE" for n in evidence["nodes"])
