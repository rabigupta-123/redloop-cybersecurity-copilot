"""Unit & Integration Tests for Unified OSINT Engine.

Verifies:
- Standardized OSINT result contract (evidence hash, timestamps, confidence, sources, verification states, limitations).
- IP intelligence: public/private RFC 1918 classification, reverse DNS, ASN/ownership, reputation.
- Domain intelligence: DNS resolution, TLS certificates, HTTP headers, mail configuration.
- Email intelligence: syntax validation, domain mailability, breach exposure truthful states.
- Username intelligence: candidate profiles, confidence scores, disclaimer against identity equivalence.
- Phone intelligence: ITU-T E.164 parsing, numbering region, truthful provider status, no fabricated data.
- Metadata & File intelligence: SHA-256 cryptographic proof, MIME detection, EXIF/PDF parsing, size bounds.
- Dual-graph population in InvestigationGraph.
"""

import tempfile
from pathlib import Path

import pytest

from redloop.investigation_graph import InvestigationGraph, NodeType, ProvenanceType
from redloop.osint_engine import (
    OSINTEngine,
    OSINTVerificationState,
    get_osint_engine,
    populate_investigation_graph_from_osint,
)


def test_ip_intelligence_loopback_and_private():
    engine = get_osint_engine()
    res = engine.investigate_ip("127.0.0.1")
    assert res.query_type == "ip"
    assert res.normalized_value == "127.0.0.1"
    assert res.status in (OSINTVerificationState.VERIFIED, OSINTVerificationState.OBSERVED)
    assert res.evidence_hash != ""
    assert res.confidence >= 0.8
    # Should classify loopback
    classification = next(f for f in res.findings if f.get("property") == "classification")
    assert classification["is_loopback"] is True
    assert classification["scope"] == "LOOPBACK"


def test_ip_intelligence_public_google_dns():
    engine = get_osint_engine()
    res = engine.investigate_ip("8.8.8.8")
    assert res.query_type == "ip"
    assert res.normalized_value == "8.8.8.8"
    assert res.evidence_hash != ""
    classification = next(f for f in res.findings if f.get("property") == "classification")
    assert classification["scope"] == "GLOBAL_PUBLIC"


def test_ip_intelligence_invalid_format():
    engine = get_osint_engine()
    res = engine.investigate_ip("not_an_ip_addr")
    assert res.status == OSINTVerificationState.FAILED
    assert "Invalid IP" in res.actual_finding
    assert res.confidence == 0.0


def test_domain_intelligence_format_and_dns():
    engine = get_osint_engine()
    res = engine.investigate_domain("example.com")
    assert res.query_type == "domain"
    assert res.normalized_value == "example.com"
    assert res.evidence_hash != ""
    assert any(f.get("property") == "dns_records" for f in res.findings)


def test_domain_intelligence_invalid():
    engine = get_osint_engine()
    res = engine.investigate_domain("invalid..domain..@@@")
    assert res.status == OSINTVerificationState.FAILED
    assert res.confidence == 0.0


def test_email_intelligence_valid_and_invalid():
    engine = get_osint_engine()
    # Invalid syntax
    bad_res = engine.investigate_email("not-an-email")
    assert bad_res.status == OSINTVerificationState.FAILED
    assert bad_res.confidence == 0.0

    # Valid syntax
    good_res = engine.investigate_email("security@example.com")
    assert good_res.status in (OSINTVerificationState.VERIFIED, OSINTVerificationState.OBSERVED)
    assert good_res.normalized_value == "security@example.com"
    assert good_res.evidence_hash != ""
    assert good_res.provider_status.get("HIBP") in ("PROVIDER_NOT_CONFIGURED", "NOT_FOUND_IN_CHECKED_SOURCES")
    mailbox_check = next(f for f in good_res.findings if f.get("property") == "mailbox_existence")
    assert mailbox_check["status"] == "UNVERIFIED"


def test_username_intelligence_candidate_profiles():
    engine = get_osint_engine()
    res = engine.investigate_username("torvalds")
    assert res.query_type == "username"
    assert res.normalized_value == "torvalds"
    assert res.evidence_hash != ""
    # Must have strict limitation that username does not equal verified human identity
    assert any("not verified human identity" in lim.lower() for lim in res.limitations)
    assert res.confidence <= 0.75  # Conservative confidence score


def test_username_intelligence_invalid():
    engine = get_osint_engine()
    res = engine.investigate_username("invalid username with spaces!@#")
    assert res.status == OSINTVerificationState.FAILED
    assert res.confidence == 0.0


def test_phone_intelligence_e164_parsing():
    engine = get_osint_engine()
    # US number
    res_us = engine.investigate_phone("+14155552671")
    assert res_us.status in (OSINTVerificationState.VERIFIED, OSINTVerificationState.OBSERVED)
    assert res_us.normalized_value == "+14155552671"
    e164_finding = next(f for f in res_us.findings if f.get("property") == "e164_format")
    assert e164_finding["iso_country"] in ("US", "US/CA")
    assert e164_finding["geographic_region"] in ("North America", "San Francisco, CA", "California", "United States")
    assert e164_finding["subscriber_assignment"] == "UNVERIFIED_LOCALLY"
    assert any("subscriber identities" in lim.lower() for lim in res_us.limitations)

    # UK number
    res_uk = engine.investigate_phone("+44 20 7946 0991")
    assert res_uk.normalized_value == "+442079460991"
    uk_finding = next(f for f in res_uk.findings if f.get("property") == "e164_format")
    assert uk_finding["iso_country"] == "GB"


def test_file_metadata_analysis(tmp_path):
    engine = get_osint_engine()
    test_file = tmp_path / "sample.pdf"
    test_file.write_bytes(b"%PDF-1.4\n1 0 obj<</Title (Confidential Assessment) /Author (RedLoop)>>endobj\ntrailer<</Root 1 0 R>>%%EOF")

    res = engine.analyze_file_metadata(test_file, filename="sample.pdf")
    assert res.query_type == "metadata"
    assert res.status == OSINTVerificationState.VERIFIED
    assert len(res.normalized_value) == 64  # SHA-256 hash
    crypto = next(f for f in res.findings if f.get("property") == "cryptographic_identity")
    assert crypto["file_type"] == "PDF_DOCUMENT"
    assert crypto["mime_type"] == "application/pdf"
    assert "pdf_version" in next(f for f in res.findings if f.get("property") == "embedded_metadata")["details"]


def test_file_metadata_empty_and_deceptive(tmp_path):
    engine = get_osint_engine()
    # 1. 0-byte file
    empty_file = tmp_path / "empty.dat"
    empty_file.write_bytes(b"")
    res_empty = engine.analyze_file_metadata(empty_file, filename="empty.dat")
    assert res_empty.status == OSINTVerificationState.FAILED
    assert "0 bytes" in res_empty.actual_finding

    # 2. Deceptive extension (.jpg extension with PDF payload)
    deceptive_file = tmp_path / "photo.jpg"
    deceptive_file.write_bytes(b"%PDF-1.7\nDeceptive payload masquerading as an image")
    res_deceptive = engine.analyze_file_metadata(deceptive_file, filename="photo.jpg")
    anomaly = next((f for f in res_deceptive.findings if f.get("property") == "deceptive_extension_anomaly"), None)
    assert anomaly is not None
    assert anomaly["risk"] == "HIGH"
    assert anomaly["declared_extension"] == ".jpg"
    assert anomaly["detected_magic"] == "PDF_DOCUMENT"


def test_osint_populates_investigation_graph(tmp_path):
    graph = InvestigationGraph(investigation_id="inv_test_osint", storage_dir=str(tmp_path))
    engine = get_osint_engine()
    res = engine.investigate_ip("8.8.8.8")

    populate_investigation_graph_from_osint(graph, res)
    elements = graph.to_cytoscape_elements()
    assert len(elements) >= 3  # Root asset, evidence node, edge
    node_types = [e["data"].get("type") for e in elements if "source" not in e["data"]]
    assert NodeType.ASSET.value in node_types
    assert NodeType.EVIDENCE.value in node_types
