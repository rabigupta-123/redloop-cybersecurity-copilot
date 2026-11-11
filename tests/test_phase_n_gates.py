"""Phase N Verification Gate Suite (N.0 Hash Length, N.1 FP Fix, N.2 CSR Headless Fallback, N.3 Three-Metric Accuracy)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3

from redloop.assessment.person_scope_gate import PersonScopeGate
from redloop.audit import AuditLogger
from redloop.email_footprint import (
    ACCOUNT_EXISTS,
    ACCOUNT_NOT_FOUND,
    ACCOUNT_RATE_LIMITED,
    ACCOUNT_UNKNOWN,
    HOLEHE_PLATFORM_CATALOG,
    HoleheEmailEnumerator,
)
from redloop.headless_fallback import (
    CONFIRMED_CSR_EMAIL_PLATFORMS,
    CONFIRMED_CSR_USERNAME_PLATFORMS,
    HeadlessRenderFallback,
    SlowPathRateLimiter,
)
from redloop.username_footprint import (
    SherlockUsernameEnumerator,
    load_platforms_catalog,
)
from scripts.run_phase_n_eval import (
    evaluate_gate_n3_rescore_m1_holdouts,
    verify_gate_n0,
    verify_gate_n1_and_n2_targeted,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def test_gate_n0_audit_hash_length_is_strictly_64_hex_chars(tmp_path: Path) -> None:
    """Verify every event_hash and prev_hash in live M.3 ledger and new audit logs is 64 hex chars."""
    n0 = verify_gate_n0()
    assert n0["all_hashes_64_hex_chars"] is True
    assert n0["verify_chain_output"]["valid"] is True
    assert n0["verify_chain_output"]["status"] == "INTEGRITY_VERIFIED"

    for row in n0["row_checks"]:
        assert row["prev_hash_len"] == 64
        assert row["event_hash_len"] == 64
        assert HEX64_RE.fullmatch(row["prev_hash"]) is not None
        assert HEX64_RE.fullmatch(row["event_hash"]) is not None

    # Also test fresh AuditLogger writes
    fresh_db = tmp_path / "n0_fresh_audit.db"
    logger = AuditLogger(str(fresh_db))
    for idx in range(5):
        logger.log(
            target=f"user{idx}@example.org",
            action="person_osint:email",
            module="assessment",
            status="BLOCKED_SCOPE_REQUIRED",
            details={"idx": idx},
        )
    assert logger.verify_chain()["valid"] is True

    conn = sqlite3.connect(str(fresh_db))
    rows = conn.execute("SELECT prev_hash, event_hash FROM audit_log ORDER BY id ASC").fetchall()
    conn.close()
    assert len(rows) == 5
    for prev_h, event_h in rows:
        assert len(prev_h) == 64
        assert len(event_h) == 64
        assert HEX64_RE.fullmatch(prev_h) is not None
        assert HEX64_RE.fullmatch(event_h) is not None


def test_gate_n1_false_positives_eliminated_on_bitbucket_and_medium() -> None:
    """Verify Bitbucket signup copy drift and Medium deleted-user soft-200 produce 0 False Positives."""
    res = verify_gate_n1_and_n2_targeted()
    n1 = res["gate_n1_false_positive_checks"]
    assert n1["bitbucket_negative_probe_state"] == ACCOUNT_NOT_FOUND
    assert n1["medium_negative_probe_state"] == ACCOUNT_NOT_FOUND
    assert n1["zero_fp_confirmed"] is True

    # Also verify that an ambiguous HTTP 200 page without a positive signature or not-found marker returns UNKNOWN (never EXISTS)
    bitbucket_spec = next(p for p in HOLEHE_PLATFORM_CATALOG if p.platform_id == "bitbucket")
    ambiguous_email_enum = HoleheEmailEnumerator(
        http_fetcher=lambda _p, _u, _e: (
            200,
            "<html><body><div class='hint'>Choose a handle that is not already taken.</div></body></html>",
        )
    )
    amb_res = ambiguous_email_enum.check_platform("test@redloop.io", bitbucket_spec)
    assert amb_res.state == ACCOUNT_UNKNOWN

    medium_spec = next(p for p in load_platforms_catalog() if p.platform_id == "medium")
    ambiguous_user_enum = SherlockUsernameEnumerator(
        platforms=[medium_spec],
        http_fetcher=lambda _p, _u, _un: (
            200,
            "<!doctype html><html><body><header>medium.com — @some_handle</header><div>Generic landing</div></body></html>",
        ),
    )
    amb_user_res = ambiguous_user_enum.check_single("some_handle", medium_spec)
    assert amb_user_res.state == ACCOUNT_UNKNOWN


def test_gate_n2_csr_headless_fallback_and_rate_limit_cap() -> None:
    """Verify CSR hydration shells escalate to headless fallback while Cloudflare 403s never escalate."""
    res = verify_gate_n1_and_n2_targeted()
    n2 = res["gate_n2_csr_headless_recovery"]

    assert n2["npmjs_positive_recovered"]["state"] == ACCOUNT_EXISTS
    assert n2["npmjs_positive_recovered"]["headless_fallback_used"] is True
    assert n2["npmjs_negative_recovered"]["state"] == ACCOUNT_NOT_FOUND
    assert n2["npmjs_negative_recovered"]["headless_fallback_used"] is True

    assert n2["patreon_positive_recovered"]["state"] == ACCOUNT_EXISTS
    assert n2["patreon_positive_recovered"]["headless_fallback_used"] is True
    assert n2["patreon_negative_recovered"]["state"] == ACCOUNT_NOT_FOUND
    assert n2["patreon_negative_recovered"]["headless_fallback_used"] is True

    assert n2["slow_path_playwright_mean_latency_ms"] > n2["fast_path_mean_latency_ms"]

    # Verify Cloudflare 403 challenge is NEVER escalated even on a CSR-enabled platform
    escalated_calls: list[str] = []
    fallback = HeadlessRenderFallback(
        allowed_platforms=frozenset({"npmjs", "vimeo"}),
        rate_limiter=SlowPathRateLimiter(rate_rps=10.0, burst=5.0),
        renderer=lambda pid, _u, _t: (escalated_calls.append(pid) or 200, "already exists"),  # type: ignore[func-returns-value]
    )
    vimeo_spec = next(p for p in HOLEHE_PLATFORM_CATALOG if p.platform_id == "vimeo")
    cf_enum = HoleheEmailEnumerator(
        http_fetcher=lambda _p, _u, _e: (
            403,
            "<html><head><title>Just a moment...</title></head><body><div id='cf-turnstile'>Verify you are human</div></body></html>",
        ),
        headless_fallback=fallback,
    )
    cf_res = cf_enum.check_platform("rabi.operator@redloop.io", vimeo_spec)
    assert cf_res.state == ACCOUNT_UNKNOWN
    assert cf_res.headless_fallback_used is False
    assert len(escalated_calls) == 0


def test_gate_n3_three_metric_accuracy_on_m1_sets() -> None:
    """Verify Resolved Accuracy >= 0.97 on both modules, 0 FP, and honest Coverage < 1.0."""
    n3 = evaluate_gate_n3_rescore_m1_holdouts()
    em = n3["email_n56"]
    us = n3["username_n60"]

    assert em["total_pairs"] == 56
    assert em["fp"] == 0
    assert em["resolved_accuracy"] >= 0.97
    assert em["strict_answered_accuracy"] == 1.0
    assert 0.90 <= em["coverage"] < 1.0
    assert len(em["resolved_accuracy_wilson_95_ci"]) == 2
    assert len(em["coverage_wilson_95_ci"]) == 2
    assert len(em["overall_accuracy_wilson_95_ci"]) == 2

    assert us["total_pairs"] == 60
    assert us["fp"] == 0
    assert us["resolved_accuracy"] >= 0.97
    assert us["strict_answered_accuracy"] == 1.0
    assert 0.90 <= us["coverage"] < 1.0
    assert len(us["resolved_accuracy_wilson_95_ci"]) == 2
    assert len(us["coverage_wilson_95_ci"]) == 2
    assert len(us["overall_accuracy_wilson_95_ci"]) == 2
