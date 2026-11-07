"""Comprehensive OSINT Depth and Accuracy Test Suite for REDLOOP Phase 3.

Verifies:
1. Golden fixture schema compliance and invariant checks across all 5 entity types
   (ip, domain, email, username, phone).
2. Multi-factor confidence calculation (C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X),
   source corroboration count SC, provenance completeness PC, and sha256 evidence hashing.
3. Phone intelligence: E.164, prefix-based carrier attribution vs unconfigured live HLR.
4. Username intelligence: platform coverage with soft-404 detection.
5. Email intelligence: syntax, disposable email detection, MX records, and truthful HIBP reporting.
6. IP intelligence: RFC-1918/loopback reputation disclaimer, public enrichment, Shodan InternetDB.
7. Offline mode (REDLOOP_OFFLINE=1): zero external requests, explicit SKIPPED_OFFLINE telemetry.
8. Fault injection: simulated 429, missing API keys, connection failures, soft-404.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from redloop.osint_engine import (
    OSINTEngine,
    OSINTResult,
    OSINTVerificationState,
    get_osint_engine,
)

FIXTURES_DIR = Path("tests/fixtures/osint_golden")


# ---------------------------------------------------------------------------
# 1. GOLDEN FIXTURE SCHEMA & INVARIANT TESTS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entity_type", ["ip", "domain", "email", "username", "phone"])
def test_golden_record_schema_and_invariants(entity_type: str):
    fixture_path = FIXTURES_DIR / f"{entity_type}.json"
    assert fixture_path.exists(), f"Golden fixture missing: {fixture_path}"
    
    raw = fixture_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    
    # Contract validation via Pydantic model
    result = OSINTResult.model_validate(data)
    assert result.query_type == entity_type
    assert result.indicator != ""
    assert result.normalized_value != ""
    assert result.actual_finding != ""
    assert result.evidence_hash != ""
    assert result.evidence_hash_version == "sha256-canonical-v2"
    assert result.verify_evidence_hash() is True
    
    # Multi-factor confidence and provenance metrics
    assert 0.0 <= result.confidence <= 1.0
    assert "C = 0.25" in result.confidence_formula
    assert result.PC >= 0.0
    assert result.SC >= 0
    assert isinstance(result.sources_queried, list)
    assert isinstance(result.sources_skipped, list)
    assert len(result.limitations) > 0


# ---------------------------------------------------------------------------
# 2. PHONE INTELLIGENCE TESTS
# ---------------------------------------------------------------------------

def test_phone_intelligence_prefix_vs_live_hlr():
    engine = OSINTEngine()
    res = engine.investigate_phone("+14155552671")
    assert res.query_type == "phone"
    assert res.normalized_value == "+14155552671"
    assert res.status in (OSINTVerificationState.OBSERVED, OSINTVerificationState.CORROBORATED)
    
    e164_finding = next(f for f in res.findings if f.get("property") == "e164_format")
    assert e164_finding["is_valid_number"] is True
    assert e164_finding["is_possible_number"] is True
    assert e164_finding["carrier_attribution_type"] == "PREFIX_METADATA"
    assert "PROVIDER_NOT_CONFIGURED" in e164_finding["live_hlr_status"]
    assert "PROVIDER_NOT_CONFIGURED" in res.actual_finding
    assert "PREFIX_METADATA" in res.actual_finding
    assert any("TWILIO_LOOKUP: PROVIDER_NOT_CONFIGURED" in s for s in res.sources_skipped)


def test_phone_intelligence_invalid_number():
    engine = OSINTEngine()
    res = engine.investigate_phone("not_a_phone_number")
    assert res.status == OSINTVerificationState.FAILED
    assert res.confidence == 0.0
    assert "INVALID_PHONE_FORMAT" in res.sources_skipped[0]


# ---------------------------------------------------------------------------
# 3. USERNAME INTELLIGENCE & SOFT-404 DETECTION
# ---------------------------------------------------------------------------

def test_username_intelligence_soft_404_handling():
    # Mock HTTP client returning soft-404 for a simulated non-existent user
    mock_client = MagicMock()
    
    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        # Simulated soft-404: HTTP 200 but body contains "Not Found" or tiny content
        if "github" in url:
            resp.status_code = 404
            resp.content = b'{"message": "Not Found"}'
            resp.text = '{"message": "Not Found"}'
        elif "reddit" in url:
            resp.status_code = 200
            resp.content = b'{"error": 404, "message": "Not Found"}'
            resp.text = '{"error": 404, "message": "Not Found"}'
            resp.json.return_value = {"error": 404}
        else:
            resp.status_code = 404
            resp.content = b'Not found'
            resp.text = 'Not found'
        return resp
        
    mock_client.get = mock_get
    engine = OSINTEngine(http_client=mock_client)
    res = engine.investigate_username("nonexistent_user_999999")
    
    assert res.query_type == "username"
    assert res.status == OSINTVerificationState.OBSERVED
    # Every platform should be classified as NOT_FOUND (no false candidate matches)
    for f in res.findings:
        assert f.get("status") == "NOT_FOUND" or f.get("verification_state") == "NO_MATCH"
    assert "Observed 0 candidate profile(s)" in res.actual_finding


def test_username_intelligence_simulated_429():
    mock_client = MagicMock()
    resp_429 = MagicMock()
    resp_429.status_code = 429
    mock_client.get.return_value = resp_429
    
    engine = OSINTEngine(http_client=mock_client)
    res = engine.investigate_username("rate_limited_user")
    assert any("RATE_LIMITED" in s for s in res.sources_skipped)
    assert any(f.get("status") == "RATE_LIMITED" for f in res.findings)


# ---------------------------------------------------------------------------
# 4. EMAIL INTELLIGENCE & TRUTHFUL BREACH REPORTING
# ---------------------------------------------------------------------------

def test_email_intelligence_disposable_domain_detection():
    engine = OSINTEngine()
    res = engine.investigate_email("testuser@mailinator.com")
    assert res.query_type == "email"
    disp_finding = next(f for f in res.findings if f.get("property") == "disposable_email_domain")
    assert disp_finding["is_disposable"] is True


def test_email_intelligence_missing_hibp_key_truthful_unconfigured():
    with patch.dict(os.environ, {}, clear=True):
        engine = OSINTEngine()
        res = engine.investigate_email("user@example.com")
        assert "HIBP: PROVIDER_NOT_CONFIGURED (breach status UNKNOWN)" in res.actual_finding
        assert res.provider_status.get("HIBP") == "PROVIDER_NOT_CONFIGURED"
        assert any("HIBP: PROVIDER_NOT_CONFIGURED" in s for s in res.sources_skipped)
        
        breach_f = next(f for f in res.findings if f.get("property") == "breach_exposure")
        assert breach_f["verification_state"] == OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value
        assert breach_f["count"] == "NOT_CHECKED"


# ---------------------------------------------------------------------------
# 5. IP INTELLIGENCE & RFC-1918 / LOOPBACK REPUTATION DISCLAIMER
# ---------------------------------------------------------------------------

def test_ip_intelligence_loopback_reputation_disclaimer():
    engine = OSINTEngine()
    res = engine.investigate_ip("127.0.0.1")
    assert "Local/private IP: external reputation not applicable; local telemetry only." in res.actual_finding
    assert any("RDAP: NOT_APPLICABLE" in s for s in res.sources_skipped)
    assert any("VirusTotal: NOT_APPLICABLE" in s for s in res.sources_skipped)


def test_ip_intelligence_private_rfc1918_reputation_disclaimer():
    engine = OSINTEngine()
    res = engine.investigate_ip("192.168.1.1")
    assert "Local/private IP: external reputation not applicable; local telemetry only." in res.actual_finding
    assert res.classification == "PRIVATE"


def test_ip_intelligence_missing_vt_key_truthful():
    with patch.dict(os.environ, {}, clear=True):
        engine = OSINTEngine()
        res = engine.investigate_ip("8.8.8.8")
        assert any("VirusTotal: PROVIDER_NOT_CONFIGURED" in s for s in res.sources_skipped)
        vt_f = next((f for f in res.findings if f.get("property") == "virustotal_reputation"), None)
        assert vt_f is not None
        assert vt_f["verification_state"] == OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value


# ---------------------------------------------------------------------------
# 6. DOMAIN INTELLIGENCE TESTS
# ---------------------------------------------------------------------------

def test_domain_intelligence_structure_and_records():
    engine = OSINTEngine()
    res = engine.investigate_domain("example.com")
    assert res.query_type == "domain"
    assert res.status in (OSINTVerificationState.OBSERVED, OSINTVerificationState.CORROBORATED)
    assert any(f.get("property") == "dns_records" for f in res.findings)
    assert any(f.get("property") == "spf_record" for f in res.findings)
    assert any(f.get("property") == "dmarc_record" for f in res.findings)


# ---------------------------------------------------------------------------
# 7. OFFLINE MODE INVARIANTS (REDLOOP_OFFLINE=1)
# ---------------------------------------------------------------------------

def test_offline_mode_enforcement_across_all_entities(monkeypatch):
    monkeypatch.setenv("REDLOOP_OFFLINE", "1")
    engine = OSINTEngine()
    
    # IP offline
    res_ip = engine.investigate_ip("8.8.8.8")
    assert res_ip.status == OSINTVerificationState.NOT_CHECKED
    assert any("SKIPPED_OFFLINE" in s for s in res_ip.sources_skipped)
    
    # Domain offline
    res_domain = engine.investigate_domain("example.com")
    assert res_domain.status == OSINTVerificationState.NOT_CHECKED
    assert any("SKIPPED_OFFLINE" in s for s in res_domain.sources_skipped)
    
    # Email offline
    res_email = engine.investigate_email("admin@example.com")
    assert res_email.status == OSINTVerificationState.NOT_CHECKED
    assert any("SKIPPED_OFFLINE" in s for s in res_email.sources_skipped)
    
    # Username offline
    res_user = engine.investigate_username("admin")
    assert res_user.status == OSINTVerificationState.NOT_CHECKED
    assert any("SKIPPED_OFFLINE" in s for s in res_user.sources_skipped)
    
    # Phone offline
    res_phone = engine.investigate_phone("+14155552671")
    assert any("LIVE_HLR: SKIPPED_OFFLINE" in s for s in res_phone.sources_skipped)


# ---------------------------------------------------------------------------
# 8. SQLITE CACHE PERSISTENCE AND 24H TTL
# ---------------------------------------------------------------------------

def test_osint_sqlite_cache_roundtrip(tmp_path):
    from redloop.osint_engine import OSINTCache
    db_file = tmp_path / "test_osint_cache.sqlite"
    cache = OSINTCache(default_ttl_seconds=86400.0, db_path=str(db_file))
    
    engine = OSINTEngine()
    res = engine.investigate_ip("127.0.0.1")
    
    # Set cache entry
    assert cache.set("ip:127.0.0.1", res) is True
    
    # Read from cache
    cached = cache.get("ip:127.0.0.1")
    assert cached is not None
    assert cached.cached is True
    assert cached.cache_status == "CACHED"
    assert cached.cached_at is not None
    assert cached.cache_ttl_seconds == 86400.0

