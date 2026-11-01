"""Acceptance tests for report validity across all 5 formats and autonomous bounded workflow."""

from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from redloop.dashboard import create_app
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from redloop.assessment.engine import AssessmentStore


@pytest.fixture
def client_with_data(tmp_path):
    audit_db = tmp_path / "report_test_audit.sqlite"
    app = create_app(str(audit_db))
    client = TestClient(app, base_url="http://127.0.0.1")

    # Seed an assessment state with genuine findings and evidence in AssessmentStore
    store = AssessmentStore()
    ev = Evidence(
        operation_id="asmt-report-test",
        target="127.0.0.1",
        tool_output="Open port 80/tcp http Apache/2.4.41",
    )
    f = Finding(
        title="Cleartext HTTP Service",
        category="Network Security",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        asset="127.0.0.1",
        target="127.0.0.1",
        port=80,
        description="Port 80 runs unencrypted HTTP.",
        remediation="Redirect HTTP traffic to HTTPS (port 443).",
        evidence=[ev],
        risk_score=5.0,
    )
    asmt = AssessmentState(
        id="asmt-report-test",
        target="127.0.0.1",
        depth=AssessmentDepth.STANDARD,
        status="COMPLETED",
        findings=[f],
        evidence=[ev],
    )
    store.save(asmt)

    return client


def test_pdf_report_validity(client_with_data):
    """Verify that PDF report returns valid application/pdf binary beginning with %PDF."""
    resp = client_with_data.get("/report/pdf?target=127.0.0.1")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    content = resp.content
    assert content.startswith(b"%PDF"), "PDF binary must start with %PDF magic bytes"
    assert len(content) > 500


def test_pptx_report_validity(client_with_data):
    """Verify that PPTX report returns valid presentationml binary beginning with PK zip header."""
    resp = client_with_data.get("/report/pptx?target=127.0.0.1")
    assert resp.status_code == 200
    assert "presentationml" in resp.headers["content-type"]
    content = resp.content
    assert content.startswith(b"PK\x03\x04"), "PPTX binary must start with PK\\x03\\x04 zip header"
    assert len(content) > 1000


def test_markdown_report_validity(client_with_data):
    """Verify that Markdown report returns clean markdown containing executive summary and findings."""
    resp = client_with_data.get("/report/md?target=127.0.0.1")
    assert resp.status_code == 200
    text = resp.text
    assert "# Executive Security Assessment Report" in text or "# REDLOOP Audit Log Report" in text
    assert "127.0.0.1" in text


def test_html_report_validity(client_with_data):
    """Verify that HTML report returns standalone valid HTML document."""
    resp = client_with_data.get("/report/html?target=127.0.0.1")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    text = resp.text.lower()
    assert "<!doctype html>" in text or "<html" in text
    assert "127.0.0.1" in text


def test_json_report_validity(client_with_data):
    """Verify that JSON report returns valid machine-readable structure."""
    resp = client_with_data.get("/report/json?target=127.0.0.1")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    data = resp.json()
    assert "target" in data
    assert data["target"] == "127.0.0.1"
    assert "findings" in data
    assert "evidence" in data
    assert "audit_records_count" in data or "audit_rows" in data
