"""Unit tests for production hardening (Phase G.3).

Verifies:
1. Token bucket rate limiting (429, burst capacity, retry-after).
2. Structured error handling (correlation ID, no raw stack trace to clients).
3. Healthz and readyz endpoints (status 200 ready, 503 degraded on broken chain/db).
4. LLM Circuit breaker state transitions (CLOSED -> OPEN -> HALF_OPEN).
5. Structured JSON logging with zero leaked secrets across all logged paths.
6. MCP tool input validation (port ranges, invalid parameters).
"""
import io
import json
import logging
import sqlite3
import time
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from redloop.hardening import (
    TokenBucket,
    RateLimiter,
    StructuredJsonFormatter,
    redact_secrets,
    LLMCircuitBreaker,
    check_readiness,
    ProductionHardeningMiddleware,
)
from redloop.connectors.mcp_server import RedloopMCPServer


# ==============================================================================
# 1. Token Bucket & Rate Limiter Tests
# ==============================================================================

def test_token_bucket_burst_and_consume():
    bucket = TokenBucket(rate=10.0, burst=5.0)
    # Should allow 5 immediate consumes
    for _ in range(5):
        assert bucket.consume(1.0) is True
    # 6th consume must fail
    assert bucket.consume(1.0) is False
    assert bucket.retry_after > 0


def test_rate_limiter_isolated_clients():
    limiter = RateLimiter(rate=5.0, burst=2.0)
    # Client A consumes 2
    assert limiter.is_allowed("192.168.1.1")[0] is True
    assert limiter.is_allowed("192.168.1.1")[0] is True
    assert limiter.is_allowed("192.168.1.1")[0] is False  # burst exceeded

    # Client B should still be allowed
    assert limiter.is_allowed("192.168.1.2")[0] is True


# ==============================================================================
# 2. Structured Error Handling & Zero Stack Trace Leaks
# ==============================================================================

async def failing_endpoint(request: Request):
    raise RuntimeError("SensitiveDatabaseConnectionException: password='SuperSecretPassword123' at db.py:42")


async def success_endpoint(request: Request):
    return JSONResponse({"status": "ok"})


@pytest.mark.asyncio
async def test_production_hardening_middleware_error_handling():
    app = Starlette(
        routes=[
            Route("/api/fail", endpoint=failing_endpoint, methods=["POST"]),
            Route("/api/ok", endpoint=success_endpoint, methods=["POST"]),
        ]
    )
    limiter = RateLimiter(rate=100.0, burst=100.0)
    app.add_middleware(ProductionHardeningMiddleware, rate_limiter=limiter)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/fail")

        assert resp.status_code == 500
        data = resp.json()
        assert data["error_code"] == "INTERNAL_SERVER_ERROR"
        assert "correlation_id" in data
        assert resp.headers.get("X-Correlation-ID") == data["correlation_id"]

        # CRITICAL: zero stack trace or exception text leaked in response body
        raw_body = resp.text
        assert "Traceback" not in raw_body
        assert "SensitiveDatabaseConnectionException" not in raw_body
        assert "SuperSecretPassword123" not in raw_body


@pytest.mark.asyncio
async def test_production_hardening_middleware_rate_limiting():
    app = Starlette(
        routes=[
            Route("/api/chat", endpoint=success_endpoint, methods=["POST"]),
        ]
    )
    # Burst of 3
    limiter = RateLimiter(rate=1.0, burst=3.0)
    app.add_middleware(ProductionHardeningMiddleware, rate_limiter=limiter)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(3):
            r = await client.post("/api/chat")
            assert r.status_code == 200

        # 4th request must be 429
        r_limited = await client.post("/api/chat")
        assert r_limited.status_code == 429
        data = r_limited.json()
        assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
        assert "retry_after_seconds" in data
        assert "Retry-After" in r_limited.headers


# ==============================================================================
# 3. Health & Readiness Tests
# ==============================================================================

def test_check_readiness_healthy(tmp_path):
    db_file = str(tmp_path / "audit.db")
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, prev_hash TEXT, event_hash TEXT)")
    cur.execute("INSERT INTO audit_log VALUES (1, 'GENESIS', 'hash1')")
    cur.execute("INSERT INTO audit_log VALUES (2, 'hash1', 'hash2')")
    conn.commit()
    conn.close()

    result = check_readiness(db_file)
    assert result["status"] == "ready"
    assert result["checks"]["database"]["status"] == "ok"
    assert result["checks"]["audit_chain"]["status"] == "ok"


def test_check_readiness_broken_chain(tmp_path):
    db_file = str(tmp_path / "broken_audit.db")
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, prev_hash TEXT, event_hash TEXT)")
    cur.execute("INSERT INTO audit_log VALUES (1, 'GENESIS', 'hash1')")
    # Broken linkage: prev_hash does not match hash1
    cur.execute("INSERT INTO audit_log VALUES (2, 'corrupt_prev_hash', 'hash2')")
    conn.commit()
    conn.close()

    result = check_readiness(db_file)
    assert result["status"] == "not_ready"
    assert result["checks"]["audit_chain"]["status"] == "broken"


# ==============================================================================
# 4. LLM Circuit Breaker
# ==============================================================================

def test_llm_circuit_breaker_transitions():
    cb = LLMCircuitBreaker(failure_threshold=3, recovery_timeout_sec=0.2)
    assert cb.can_execute() is True
    assert cb.state == "CLOSED"

    # 1st and 2nd failure
    cb.record_failure()
    assert cb.state == "CLOSED"
    assert cb.can_execute() is True
    cb.record_failure()
    assert cb.state == "CLOSED"

    # 3rd failure trips OPEN
    cb.record_failure()
    assert cb.state == "OPEN"
    assert cb.can_execute() is False

    # Wait for recovery timeout
    time.sleep(0.25)
    # Next call transitions to HALF_OPEN
    assert cb.can_execute() is True
    assert cb.state == "HALF_OPEN"

    # Success closes the circuit
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.failure_count == 0


# ==============================================================================
# 5. Secret Redaction & Structured Logging Tests
# ==============================================================================

KNOWN_SECRETS = [
    "gsk_0123456789abcdef0123456789abcdef",
    "sk-proj-test123456fakeexamplekey999",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_jwt_token",
    'api_key="AKIA1234567890EXAMPLE"',
    "password: 'SuperSecretDatabasePassword'",
]


@pytest.mark.parametrize("secret", KNOWN_SECRETS)
def test_redact_secrets_cleans_known_patterns(secret: str):
    msg = f"Operation failed while connecting with token {secret} to target."
    cleaned = redact_secrets(msg)
    assert secret not in cleaned
    assert "[REDACTED_SECRET]" in cleaned


def test_structured_json_formatter_redacts_and_formats():
    formatter = StructuredJsonFormatter()
    logger_instance = logging.getLogger("test_redact_logger")
    logger_instance.handlers.clear()

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger_instance.addHandler(handler)
    logger_instance.setLevel(logging.INFO)

    secret = "gsk_test1234567890abcdefghijklmnopqrstuvwxyz"
    logger_instance.info(f"Connecting to provider using {secret}")

    output = stream.getvalue().strip()
    assert output, "Log output should not be empty"

    log_json = json.loads(output)
    assert log_json["level"] == "INFO"
    assert secret not in log_json["message"]
    assert "[REDACTED_SECRET]" in log_json["message"]
    assert "timestamp" in log_json


# ==============================================================================
# 6. MCP Input Validation Tests
# ==============================================================================

@pytest.mark.anyio
async def test_mcp_scope_check_port_validation():
    server = RedloopMCPServer()

    # Invalid port (0)
    res_zero = await server.mcp.call_tool("scope_check", {"target": "127.0.0.1", "port": 0})
    content_str = str(res_zero.content[0])
    assert "invalid" in content_str.lower() or "INVALID_PORT" in content_str

    # Invalid port (> 65535)
    res_overflow = await server.mcp.call_tool("scope_check", {"target": "127.0.0.1", "port": 70000})
    content_str = str(res_overflow.content[0])
    assert "invalid" in content_str.lower() or "INVALID_PORT" in content_str


@pytest.mark.anyio
async def test_mcp_run_recon_port_validation():
    server = RedloopMCPServer()
    res = await server.mcp.call_tool("run_recon", {"target": "10.0.0.1", "port": 99999})
    content_str = str(res.content[0])
    assert "invalid" in content_str.lower() or "INVALID_PORT" in content_str


# ==============================================================================
# 7. Signed Findings & Metrics API Tests (Phase H.5)
# ==============================================================================

def test_signed_findings_export_and_tamper_detection():
    from redloop.assessment.findings_signer import export_signed_findings, verify_signed_findings

    test_findings = [
        {"id": "FIND-001", "severity": "HIGH", "title": "SQL Injection in Login"},
        {"id": "FIND-002", "severity": "MEDIUM", "title": "Missing Rate Limiting"},
    ]
    secret = "test-bounty-signing-key-123"
    dossier = export_signed_findings("eng-bounty-alpha", test_findings, secret=secret)

    # Valid signature
    assert verify_signed_findings(dossier, secret=secret) is True

    # Tampered finding should fail verification
    tampered = dict(dossier)
    tampered["findings"] = [{"id": "FIND-001", "severity": "LOW", "title": "Altered Severity"}]
    assert verify_signed_findings(tampered, secret=secret) is False

