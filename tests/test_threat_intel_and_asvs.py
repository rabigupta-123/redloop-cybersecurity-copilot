"""Unit tests for Threat Intelligence Engine and OWASP ASVS Verification."""

import pytest
from redloop.threat_intel import get_threat_intel_engine
from redloop.asvs import get_asvs_engine


def test_cisa_kev_known_cve():
    ti = get_threat_intel_engine()
    res = ti.query_cve("CVE-2021-44228")

    assert res.cve_id == "CVE-2021-44228"
    assert res.in_cisa_kev is True
    assert res.cisa_kev_due_date is not None
    assert res.epss_score is not None
    assert res.epss_score > 0.8
    assert res.evidence_hash is not None


def test_cisa_kev_unknown_cve():
    ti = get_threat_intel_engine()
    res = ti.query_cve("CVE-1999-99999")

    assert res.cve_id == "CVE-1999-99999"
    assert res.in_cisa_kev is False
    assert res.epss_score is not None


def test_ip_reputation_query():
    ti = get_threat_intel_engine()
    res = ti.query_ip_reputation("127.0.0.1")

    assert res.indicator == "127.0.0.1"
    assert res.status in ("CLEAN", "NO_RECORDS")
    assert res.evidence_hash is not None


def test_asvs_headers_evaluation_simulated():
    engine = get_asvs_engine()
    # Mock evaluate against a synthetic test URL (won't crash if connection fails)
    report = engine.evaluate_url("http://127.0.0.1:8765", test_endpoints=False)

    assert report.target_url == "http://127.0.0.1:8765"
    assert len(report.controls) > 0
    # Controls should include 14.4.1 (HSTS), 14.4.2 (CSP), 14.4.3 (XCTO), 14.4.4 (XFO)
    control_ids = [c["control_id"] for c in report.controls]
    assert "14.4.1" in control_ids
    assert "14.4.2" in control_ids
    assert "14.4.3" in control_ids
    assert "14.4.4" in control_ids
    assert report.evidence_hash is not None
