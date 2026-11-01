import base64

import httpx
import pytest

from redloop.virustotal import (
    ST_ANALYSIS_PENDING,
    ST_API_UNAVAILABLE,
    ST_CACHED,
    ST_INVALID_INPUT,
    ST_LIVE,
    ST_NOT_FOUND,
    ST_RATE_LIMITED,
    UPLOAD_CONSENT_TOKEN,
    VirusTotalClient,
)

VT_STATS = {
    "malicious": 2,
    "suspicious": 1,
    "harmless": 5,
    "undetected": 2,
    "timeout": 1,
    "failure": 0,
    "type-unsupported": 0,
}


def _payload(stats=None, **attrs):
    attributes = {
        "last_analysis_stats": VT_STATS if stats is None else stats,
        "reputation": -12,
        "categories": {"engine": "malware"},
        "tags": ["test"],
        "last_analysis_date": 1700000000,
        **attrs,
    }
    return {"data": {"id": "abc123", "attributes": attributes}}


def _client(handler, *, key="vt-test-key", clock=lambda: 1000.0, ttl=60):
    return VirusTotalClient(
        api_key=key,
        base_url="https://vt.test/api/v3",
        transport=httpx.MockTransport(handler),
        clock=clock,
        cache_ttl=ttl,
    )


def test_missing_key_is_not_reported_as_clean():
    client = VirusTotalClient(api_key="", enabled=True, transport=httpx.MockTransport(lambda r: None))
    result = client.inspect("8.8.8.8")

    assert result.status == ST_API_UNAVAILABLE
    assert result.verdict == "UNKNOWN"
    assert result.detection_ratio is None
    assert result.evidence_hash
    assert result.verify_evidence_hash()
    assert "VIRUSTOTAL_API_KEY" in (result.reason or "")


def test_disabled_provider_is_not_reported_as_clean():
    client = VirusTotalClient(
        api_key="key",
        enabled=False,
        base_url="https://vt.test/api/v3",
        transport=httpx.MockTransport(lambda r: None),
    )
    result = client.inspect("example.com")
    assert result.status == ST_API_UNAVAILABLE
    assert "disabled" in (result.reason or "").lower()


@pytest.mark.parametrize("value", ["", "not-an-indicator", "http://", "999.1.1.1", "zzz"])
def test_invalid_indicator_never_calls_api(value):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=_payload())

    result = _client(handler).inspect(value)
    assert result.status == ST_INVALID_INPUT
    assert calls == []


def test_ip_result_normalises_ratio_and_coverage():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json=_payload())

    result = _client(handler).inspect("8.8.8.8")

    assert result.status == ST_LIVE
    assert result.live is True
    assert result.indicator_type == "ip"
    assert seen["url"].endswith("/ip_addresses/8.8.8.8")
    assert result.malicious == 2
    assert result.verdict_engines == 10
    assert result.total_engines == 11
    assert result.detection_ratio == pytest.approx(0.2)
    assert result.engine_coverage["ratio"] == pytest.approx(10 / 11)
    assert result.detection_ratio_status == "AVAILABLE"
    assert result.verdict == "MALICIOUS_DETECTIONS_PRESENT"
    assert result.last_analysis_date is not None
    assert result.evidence_hash == result.compute_evidence_hash()


def test_domain_and_url_endpoints_are_distinct():
    urls = []

    def handler(request):
        urls.append(str(request.url))
        return httpx.Response(200, json=_payload())

    client = _client(handler)
    client.inspect("example.com")
    client.inspect("https://example.com/a?b=1")

    assert urls[0].endswith("/domains/example.com")
    expected = base64.urlsafe_b64encode(b"https://example.com/a?b=1").decode().rstrip("=")
    assert urls[1].endswith(f"/urls/{expected}")


def test_second_lookup_is_explicitly_cached_and_keeps_evidence():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=_payload())

    client = _client(handler)
    first = client.inspect("1.1.1.1")
    second = client.inspect("1.1.1.1")

    assert len(calls) == 1
    assert first.status == ST_LIVE
    assert second.status == ST_CACHED
    assert second.from_cache is True
    assert second.live is False
    assert second.malicious == first.malicious
    assert second.evidence_hash == first.evidence_hash


def test_cache_expiry_performs_live_request():
    now = [1000.0]
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=_payload())

    client = _client(handler, clock=lambda: now[0], ttl=10)
    client.inspect("1.1.1.1")
    now[0] = 1011.0
    result = client.inspect("1.1.1.1")
    assert len(calls) == 2
    assert result.status == ST_LIVE


@pytest.mark.parametrize(
    "status,expected",
    [
        (404, ST_NOT_FOUND),
        (429, ST_RATE_LIMITED),
        (401, ST_API_UNAVAILABLE),
        (403, ST_API_UNAVAILABLE),
        (500, ST_API_UNAVAILABLE),
        (418, ST_API_UNAVAILABLE),
    ],
)
def test_http_failures_are_never_clean(status, expected):
    result = _client(lambda request: httpx.Response(status)).inspect("8.8.8.8")
    assert result.status == expected
    assert result.verdict == "UNKNOWN"
    assert result.detection_ratio is None


def test_timeout_is_api_unavailable():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    result = _client(handler).inspect("8.8.8.8")
    assert result.status == ST_API_UNAVAILABLE
    assert "timed out" in (result.reason or "").lower()


def test_zero_engine_stats_are_not_available_not_zero_risk():
    result = _client(
        lambda request: httpx.Response(200, json=_payload(stats={}))
    ).inspect("8.8.8.8")

    assert result.status == ST_LIVE
    assert result.detection_ratio is None
    assert result.detection_ratio_status == "NOT_AVAILABLE"
    assert result.verdict == "UNKNOWN"


def test_evidence_hash_detects_tampering():
    result = _client(lambda request: httpx.Response(200, json=_payload())).inspect("8.8.8.8")
    result.malicious = 99
    assert result.verify_evidence_hash() is False


def test_base_url_rejects_metadata_hosts():
    with pytest.raises(ValueError):
        VirusTotalClient(api_key="k", base_url="http://169.254.169.254/latest")
    with pytest.raises(ValueError):
        VirusTotalClient(api_key="k", base_url="http://metadata.google.internal/")


def test_provider_status_never_leaks_key():
    status = VirusTotalClient(
        api_key="supersecretapikey", base_url="https://vt.test/api/v3"
    ).provider_status()
    assert status["status"] == "CONFIGURED"
    assert status["api_key_masked"] == "supe...ikey"
    assert "supersecretapikey" not in str(status)


@pytest.mark.parametrize(
    "value,declared",
    [
        ("8.8.8.8", "domain"),
        ("example.com", "ip"),
        ("example.com", "url"),
        ("https://example.com/a", "domain"),
        ("a" * 64, "ip"),
    ],
)
def test_declared_type_mismatch_is_rejected_before_api(value, declared):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=_payload())

    result = _client(handler).inspect(value, declared)
    assert result.status == ST_INVALID_INPUT
    assert result.verify_evidence_hash()
    assert calls == []


def test_malformed_declared_ip_is_rejected_without_raising():
    result = _client(lambda request: httpx.Response(200, json=_payload())).inspect(
        "999.1.1.1", "ip"
    )
    assert result.status == ST_INVALID_INPUT
    assert result.verify_evidence_hash()


def test_cached_result_preserves_provenance_timestamps():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=_payload())

    client = _client(handler)
    first = client.inspect("1.1.1.1")
    second = client.inspect("1.1.1.1")

    assert len(calls) == 1
    assert second.status == ST_CACHED
    assert second.source_status == ST_LIVE
    assert second.observed_at == first.observed_at
    assert second.fetched_at == first.fetched_at
    assert second.cache_expires_at
    assert second.verify_evidence_hash()


def test_pending_analysis_is_explicit_and_not_cached():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(409)

    client = _client(handler)
    first = client.inspect("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "file")
    second = client.inspect("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "file")

    assert first.status == ST_ANALYSIS_PENDING
    assert second.status == ST_ANALYSIS_PENDING
    assert len(calls) == 2
    assert first.verdict == "UNKNOWN"


def test_malformed_payload_is_unavailable_not_clean():
    result = _client(lambda request: httpx.Response(200, text="not json")).inspect("8.8.8.8")
    assert result.status == ST_API_UNAVAILABLE
    assert result.verdict == "UNKNOWN"
    assert result.verify_evidence_hash()


def test_zero_detections_are_not_labelled_safe():
    stats = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 8,
        "undetected": 2,
        "timeout": 0,
        "failure": 0,
        "type-unsupported": 0,
    }
    result = _client(lambda request: httpx.Response(200, json=_payload(stats=stats))).inspect(
        "8.8.8.8"
    )
    assert result.verdict == "NO_SECURITY_VENDOR_DETECTIONS"
    assert result.detection_ratio == 0.0
    assert "safe" not in result.verdict.lower()


def test_cached_file_result_covers_file_hashes_in_evidence():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    client = _client(handler)
    first = client.analyse_file_bytes("sample.bin", b"hello world")
    second = client.analyse_file_bytes("sample.bin", b"hello world")

    assert first.status == ST_NOT_FOUND
    assert second.status == ST_CACHED
    assert first.file_hashes == second.file_hashes
    assert first.verify_evidence_hash()
    assert second.verify_evidence_hash()
    assert first.evidence_hash == second.evidence_hash
    second.file_hashes["sha256"] = "0" * 64
    assert second.verify_evidence_hash() is False
    assert first.verify_evidence_hash() is True


def test_file_hash_lookup_and_consent_gated_upload():
    calls = []

    def handler(request):
        calls.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        return httpx.Response(200, json={"data": {"id": "analysis-id"}})

    client = _client(handler)
    no_upload = client.analyse_file_bytes("sample.bin", b"hello world")
    assert no_upload.status == ST_NOT_FOUND
    assert "not requested" in (no_upload.reason or "").lower()
    assert no_upload.file_hashes["sha256"]
    assert len(calls) == 1

    wrong = client.analyse_file_bytes("sample.bin", b"hello world", upload=True, consent_token="nope")
    assert wrong.status == ST_INVALID_INPUT
    assert len(calls) == 1

    pending = client.analyse_file_bytes(
        "sample.bin",
        b"hello world",
        upload=True,
        consent_token=UPLOAD_CONSENT_TOKEN,
    )
    assert pending.status == ST_ANALYSIS_PENDING
    assert len(calls) == 2
    assert calls[1][0] == "POST"


def test_existing_file_hash_does_not_upload():
    client = _client(
        lambda request: httpx.Response(
            200,
            json=_payload(sha256="a" * 64, md5="a" * 32, sha1="a" * 40),
        )
    )
    result = client.analyse_file_bytes(
        "sample.bin", b"hello", upload=True, consent_token=UPLOAD_CONSENT_TOKEN
    )
    assert result.status == ST_LIVE
    assert result.indicator_type == "file"
