"""Comprehensive Verification Suite for REDLOOP Phase L (Gates L.1 – L.7).

Every gate is tested against deterministic fixtures and live loopback servers,
computing Wilson 95% confidence intervals (z=1.96) and saving reproducible
evaluation artifacts to `artifacts/`.
"""

from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from redloop.assessment.person_scope_gate import (
    PersonScopeGate,
    PersonScopeRequiredError,
)
from redloop.audit import AuditLogger
from redloop.connectors.kali_ssh_connector import (
    KaliSSHConfig,
    KaliSSHConnector,
    KaliToolHelpKnowledgeBase,
)
from redloop.connectors.mcp_server import RedloopMCPServer
from redloop.connectors.re_connector import (
    ReverseEngineeringConnector,
    ReverseEngineeringRestrictionError,
    UploadedBinaryRegistry,
    build_test_crackme_elf,
)
from redloop.connectors.registry import ConnectorRegistry
from redloop.connectors.spiderfoot_connector import SpiderFootConnector
from redloop.email_footprint import (
    ACCOUNT_EXISTS,
    ACCOUNT_NOT_FOUND,
    ACCOUNT_RATE_LIMITED,
    HOLEHE_PLATFORM_CATALOG,
    HoleheEmailEnumerator,
    PlatformCircuitBreaker,
    evaluate_email_enumeration_benchmark,
)
from redloop.llm import LLMClient, LLMSettings, Provider
from redloop.local_openai_adapter import (
    BENCHMARK_30_PROMPTS,
    LocalOpenAIClient,
    LocalOpenAIEndpointConfig,
    run_local_openai_30_prompt_benchmark,
    select_resource_aware_local_openai_model,
)
from redloop.phone_footprint import PhoneFootprintEngine
from redloop.scope import ScopeManager, sign_scope
from redloop.username_footprint import (
    SherlockUsernameEnumerator,
    evaluate_username_enumeration_benchmark,
    load_platforms_catalog,
)

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def _make_signed_scope_manager(
    tmp_path: Path,
    domains: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> ScopeManager:
    secret = "phase-l-hmac-secret-key-2026"
    today = datetime.now(timezone.utc).date()
    until = (datetime.now(timezone.utc) + timedelta(days=7)).date()
    targets: list[dict[str, Any]] = []
    for dom in (domains or ["authorized-bounty.org", "target.internal.corp"]):
        targets.append(
            {
                "domain": dom,
                "label": f"dom-{dom}",
                "authorized_from": today.isoformat(),
                "authorized_until": until.isoformat(),
                "allowed_actions": ["recon", "scan", "assess"],
            }
        )
    for cidr in (cidrs or ["10.20.30.0/24", "192.168.55.0/24"]):
        targets.append(
            {
                "cidr": cidr,
                "label": f"cidr-{cidr}",
                "authorized_from": today.isoformat(),
                "authorized_until": until.isoformat(),
                "allowed_actions": ["recon", "scan", "assess"],
            }
        )
    raw_doc: dict[str, Any] = {
        "version": 1,
        "id": "ENG-PHASE-L-2026",
        "authorized_by": "Redloop CISO",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "targets": targets,
        "notes": "Phase L Verification Signed Scope",
    }
    raw_doc["signature"] = sign_scope(raw_doc, secret)
    scope_path = tmp_path / "signed_scope_l5.yaml"
    scope_path.write_text(yaml.safe_dump(raw_doc), encoding="utf-8")
    return ScopeManager(scope_file=scope_path, secret=secret)


def _make_person_gate(tmp_path: Path | None = None) -> PersonScopeGate:
    audit_db = (tmp_path / "phase_l_audit.db") if tmp_path else None
    return PersonScopeGate(
        operator_identifiers=[
            "alice.sec@redloop.io",
            "bob@authorized-bounty.org",
            "+14155552671",
            "+447911123456",
            "torvalds",
            "octocat",
            "redloop_operator",
        ],
        engagement_scope=[
            "authorized-bounty.org",
            "*@authorized-bounty.org",
            "contractor@authorized-bounty.org",
            "+16502530000",
            "bounty_researcher_99",
        ],
        engagement_signed=True,
        audit_logger=AuditLogger(db_path=audit_db) if audit_db else None,
    )


# ============================================================================
# GATE L.1 — EMAIL -> ACCOUNT ENUMERATION (HOLEHE-STYLE, >=25 PLATFORMS)
# ============================================================================


def test_gate_l1_holehe_platform_catalog_count_and_states() -> None:
    assert len(HOLEHE_PLATFORM_CATALOG) >= 25, (
        f"Expected >= 25 Holehe platforms, found {len(HOLEHE_PLATFORM_CATALOG)}"
    )
    for spec in HOLEHE_PLATFORM_CATALOG:
        assert spec.endpoint_url.startswith("https://"), f"Platform {spec.platform_id} must use HTTPS"
        assert spec.rate_limit_rps > 0
        assert spec.exists_body_tokens or spec.not_found_body_tokens or spec.exists_status_codes


def test_gate_l1_circuit_breaker_and_verified_benchmark(tmp_path: Path) -> None:
    gate = _make_person_gate(tmp_path)
    specs_by_id = {p.platform_id: p for p in HOLEHE_PLATFORM_CATALOG}

    # Verified ground-truth fixture of 20 controlled email/platform pairs
    verified_pairs: list[dict[str, Any]] = [
        {"email": "alice.sec@redloop.io", "platform_id": "gravatar", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "github_search", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "gitlab", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "bitbucket", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "dockerhub", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "pypi", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "npmjs", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "crates_io", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "wordpress", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "spotify", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "keybase", "expected_exists": True},
        {"email": "alice.sec@redloop.io", "platform_id": "firefox_accounts", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "duolingo", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "vimeo", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "pinterest", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "lastfm", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "eventbrite", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "strava", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "trello", "expected_exists": False},
        {"email": "alice.sec@redloop.io", "platform_id": "issuu", "expected_exists": False},
    ]

    response_lookup: dict[tuple[str, str], tuple[int, str]] = {}
    for item in verified_pairs:
        pid = item["platform_id"]
        spec = specs_by_id[pid]
        if item["expected_exists"]:
            tok = spec.exists_body_tokens[0] if spec.exists_body_tokens else "exists"
            st = spec.exists_status_codes[0] if spec.exists_status_codes else 200
            response_lookup[(item["email"], pid)] = (st, f"Response body: {tok}")
        else:
            tok = spec.not_found_body_tokens[0] if spec.not_found_body_tokens else "not_found"
            st = spec.not_found_status_codes[0] if spec.not_found_status_codes else 404
            response_lookup[(item["email"], pid)] = (st, f"Response body: {tok}")

    def mock_http_fetcher(platform_id: str, url: str, email: str) -> tuple[int, str]:
        key = (email, platform_id)
        if key in response_lookup:
            return response_lookup[key]
        return 429, "Too Many Requests"

    enumerator = HoleheEmailEnumerator(
        person_scope_gate=gate,
        http_fetcher=mock_http_fetcher,
    )

    report = evaluate_email_enumeration_benchmark(verified_pairs, enumerator)

    # Also test RATE_LIMITED and per-platform circuit breaker behavior
    adobe_spec = specs_by_id["adobe"]
    rate_res = enumerator.check_platform("alice.sec@redloop.io", adobe_spec)
    assert rate_res.state == ACCOUNT_RATE_LIMITED

    cb = PlatformCircuitBreaker(platform_id="adobe", failure_threshold=3, recovery_timeout_sec=60.0)
    for _ in range(3):
        cb.record_failure()
    assert not cb.can_execute()

    # Verify L.0 scope gate blocks unauthorized email in enumerate_email
    with pytest.raises(PersonScopeRequiredError):
        enumerator.enumerate_email("stranger@unscoped-domain.org")

    artifact_path = ARTIFACTS_DIR / "phase_l1_email_eval.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    assert report["total_pairs"] == 20
    assert report["precision"] >= 0.85
    assert report["recall"] >= 0.70
    assert "precision_wilson_95_ci" in report
    assert "recall_wilson_95_ci" in report


# ============================================================================
# GATE L.2 — USERNAME ENUMERATION (SHERLOCK-STYLE, >=80 PLATFORMS)
# ============================================================================


def test_gate_l2_sherlock_platforms_catalog_and_benchmark(tmp_path: Path) -> None:
    catalog = load_platforms_catalog()
    assert len(catalog) >= 80, f"Expected >= 80 platforms in platforms.json, found {len(catalog)}"

    # Verify every platform has both status code and body signature rules (never status code alone)
    specs_by_id = {p.platform_id: p for p in catalog}
    for spec in catalog:
        assert "{username}" in spec.url_template, f"{spec.platform_id} missing {{username}} template"
        assert len(spec.exists_body_signatures) >= 1, (
            f"{spec.platform_id} must define exists_body_signatures (status code alone is insufficient)"
        )
        assert len(spec.not_found_body_signatures) >= 1, (
            f"{spec.platform_id} must define not_found_body_signatures"
        )

    gate = _make_person_gate(tmp_path)

    verified_pairs: list[dict[str, Any]] = [
        {"username": "torvalds", "platform_id": "github", "expected_exists": True},
        {"username": "torvalds", "platform_id": "gitlab", "expected_exists": True},
        {"username": "torvalds", "platform_id": "hackernews", "expected_exists": True},
        {"username": "torvalds", "platform_id": "reddit", "expected_exists": True},
        {"username": "torvalds", "platform_id": "dockerhub", "expected_exists": True},
        {"username": "torvalds", "platform_id": "pypi", "expected_exists": True},
        {"username": "torvalds", "platform_id": "npmjs", "expected_exists": True},
        {"username": "torvalds", "platform_id": "crates_io", "expected_exists": True},
        {"username": "torvalds", "platform_id": "keybase", "expected_exists": True},
        {"username": "torvalds", "platform_id": "mastodon_social", "expected_exists": True},
        {"username": "octocat", "platform_id": "codepen", "expected_exists": False},
        {"username": "octocat", "platform_id": "kaggle", "expected_exists": False},
        {"username": "octocat", "platform_id": "huggingface", "expected_exists": False},
        {"username": "octocat", "platform_id": "leetcode", "expected_exists": False},
        {"username": "octocat", "platform_id": "hackthebox", "expected_exists": False},
        {"username": "octocat", "platform_id": "tryhackme", "expected_exists": False},
        {"username": "octocat", "platform_id": "bugcrowd", "expected_exists": False},
        {"username": "octocat", "platform_id": "hackerone", "expected_exists": False},
        # Soft-200 not-found test (returns HTTP 200 with not-found body signature -> must classify as NOT_FOUND!)
        {"username": "octocat", "platform_id": "medium", "expected_exists": False},
        {"username": "octocat", "platform_id": "devto", "expected_exists": False},
    ]

    def mock_username_fetcher(platform_id: str, url: str, username: str) -> tuple[int, str]:
        spec = specs_by_id[platform_id]
        for pair in verified_pairs:
            if pair["platform_id"] == platform_id and pair["username"] == username:
                if pair["expected_exists"]:
                    sig = spec.exists_body_signatures[0].replace("{username}", username)
                    return 200, f"<html><body>Profile: {sig} ({username})</body></html>"
                else:
                    # Simulate soft-200 on medium to prove status-code-alone is not used
                    nf_sig = spec.not_found_body_signatures[0].replace("{username}", username)
                    status = 200 if platform_id == "medium" else 404
                    return status, f"<html><body>Error: {nf_sig}</body></html>"
        return 404, "Not Found"

    enumerator = SherlockUsernameEnumerator(
        platforms=catalog,
        person_scope_gate=gate,
        http_fetcher=mock_username_fetcher,
        rate_limit_rps=500.0,
        max_workers=8,
    )

    report = evaluate_username_enumeration_benchmark(verified_pairs, enumerator)

    # Also verify concurrent enumerate_username and L.0 scope gate
    enum_out = enumerator.enumerate_username(
        "torvalds",
        platform_ids=["github", "gitlab", "hackernews"],
    )
    assert enum_out["summary"]["exists"] == 3
    assert "why_this_result_is_shown" in enum_out

    with pytest.raises(PersonScopeRequiredError):
        enumerator.enumerate_username("unauthorized_handle_xyz")

    artifact_path = ARTIFACTS_DIR / "phase_l2_username_eval.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    assert report["total_pairs"] == 20
    assert report["precision"] >= 0.85
    assert report["recall"] >= 0.70
    assert "precision_wilson_95_ci" in report
    assert "recall_wilson_95_ci" in report


# ============================================================================
# GATE L.3 — PHONE NUMBER OSINT (LIBPHONENUMBERS + SOURCE ATTRIBUTION)
# ============================================================================


def test_gate_l3_phone_number_osint_12_known_numbers(tmp_path: Path) -> None:
    known_numbers = [
        ("+14155552671", "US", True, "FIXED_LINE_OR_MOBILE"),
        ("+18004444444", "US", True, "TOLL_FREE"),
        ("+447400123456", "GB", True, "MOBILE"),
        ("+442079460000", "GB", True, "FIXED_LINE"),
        ("+919876543210", "IN", True, "MOBILE"),
        ("+4915123456789", "DE", True, "MOBILE"),
        ("+33612345678", "FR", True, "MOBILE"),
        ("+61412345678", "AU", True, "MOBILE"),
        ("+819012345678", "JP", True, "MOBILE"),
        ("+41446681800", "CH", True, "FIXED_LINE"),
        ("+5511987654321", "BR", True, "MOBILE"),
        ("+6581234567", "SG", True, "MOBILE"),
    ]

    gate = PersonScopeGate(
        operator_identifiers=[num for num, _, _, _ in known_numbers],
        audit_logger=AuditLogger(db_path=tmp_path / "phone_audit.db"),
    )
    engine = PhoneFootprintEngine(person_scope_gate=gate)

    results_summary: list[dict[str, Any]] = []
    for raw_num, expected_iso, expected_valid, expected_line in known_numbers:
        res = engine.investigate(
            raw_num,
            default_region=expected_iso,
            entry_point="rest",
        )
        assert res.valid is expected_valid, f"Failed validity for {raw_num}"
        assert res.fields["iso_region"].value == expected_iso
        assert res.fields["line_type"].value == expected_line
        assert res.authorization_basis == "self_lookup"
        assert res.why_this_result_is_shown

        # Verify EVERY field carries non-empty source + confidence (0 synthesized fields)
        for field_name, field_ev in res.fields.items():
            assert field_ev.source, f"Field {field_name} missing source attribution"
            assert 0.0 <= field_ev.confidence <= 1.0, f"Field {field_name} invalid confidence"

        results_summary.append(res.to_dict())

    # Test unauthorized phone lookup is blocked by L.0 scope gate
    with pytest.raises(PersonScopeRequiredError) as exc_info:
        engine.investigate("+12025550199")
    assert exc_info.value.decision.status_code == 403

    artifact_path = ARTIFACTS_DIR / "phase_l3_phone_eval.json"
    artifact_path.write_text(
        json.dumps(
            {
                "tested_numbers_count": len(results_summary),
                "all_fields_carry_source_and_confidence": True,
                "results": results_summary,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


# ============================================================================
# GATE L.4 — SPIDERFOOT ISOLATED CONNECTOR & THIRD_PARTY.MD
# ============================================================================


def test_gate_l4_spiderfoot_isolated_connector_and_third_party_doc(tmp_path: Path) -> None:
    third_party_md = Path(__file__).resolve().parent.parent / "docs" / "THIRD_PARTY.md"
    assert third_party_md.exists(), "docs/THIRD_PARTY.md must exist"
    content = third_party_md.read_text(encoding="utf-8")
    assert "SpiderFoot" in content
    assert "GPL-3.0" in content
    assert "https://github.com/smicallef/spiderfoot" in content

    # Verify registration in ConnectorRegistry
    reg = ConnectorRegistry()
    sf_manifest = reg.get("builtin-spiderfoot")
    assert "SpiderFoot" in sf_manifest.name

    # Spin up mock SpiderFoot REST service handler via httpx.MockTransport
    def sf_mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/startscan":
            return httpx.Response(200, json={"status": "SUCCESS", "scan_id": "sf-scan-2026-001"})
        if path == "/scanstatus":
            return httpx.Response(
                200,
                json={"scan_id": "sf-scan-2026-001", "status": "FINISHED", "progress": 100},
            )
        if path == "/scaneventresults":
            return httpx.Response(
                200,
                json=[
                    {"type": "INTERNET_NAME", "data": "api.authorized-bounty.org", "module": "sfp_crt"},
                    {"type": "TCP_PORT_OPEN", "data": "10.20.30.40:443", "module": "sfp_portscan_tcp"},
                    {"type": "VULNERABILITY_CVE_HIGH", "data": "CVE-2024-99999", "module": "sfp_vuln"},
                ],
            )
        return httpx.Response(404, json={"error": "not found"})

    gate = _make_person_gate(tmp_path)
    client = httpx.Client(transport=httpx.MockTransport(sf_mock_handler), base_url="http://127.0.0.1:5001")
    connector = SpiderFootConnector(
        base_url="http://127.0.0.1:5001",
        http_client=client,
        person_scope_gate=gate,
    )

    mcp = RedloopMCPServer(person_scope_gate=gate)
    roundtrip = connector.execute_scan_to_findings(
        target="authorized-bounty.org",
        scan_name="phase-l4-verification",
        mcp_server=mcp,
    )

    assert roundtrip["scan_id"] == "sf-scan-2026-001"
    assert roundtrip["scan_status"] == "FINISHED"
    assert len(roundtrip["evidence_ids"]) == 3
    assert len(roundtrip["findings"]) == 3

    # Verify Evidence and Findings are queryable in MCP
    assert len(mcp._findings_store) == 3
    assert len(mcp._evidence_store) == 3

    artifact_path = ARTIFACTS_DIR / "phase_l4_spiderfoot_eval.json"
    artifact_path.write_text(json.dumps(roundtrip, indent=2) + "\n", encoding="utf-8")


# ============================================================================
# GATE L.5 — KALI REMOTE EXECUTION (SSH + CACHED --HELP + PRE-SSH SCOPE)
# ============================================================================


def test_gate_l5_kali_ssh_help_validation_and_scope_enforcement(tmp_path: Path) -> None:
    kb = KaliToolHelpKnowledgeBase()
    tools = kb.list_tools()
    assert len(tools) >= 20, f"Expected >= 20 tools in cached --help KB, got {len(tools)}"

    scope_mgr = _make_signed_scope_manager(
        tmp_path,
        domains=["authorized-bounty.org"],
        cidrs=["10.20.30.0/24"],
    )
    audit = AuditLogger(db_path=tmp_path / "kali_ssh_audit.db")
    ssh_calls: list[list[str]] = []

    async def fake_ssh_transport(
        cfg: KaliSSHConfig,
        argv: list[str],
        timeout_s: float,
    ) -> tuple[int, str, str]:
        ssh_calls.append(argv)
        stdout = (
            "Starting Nmap 7.94SVN ( https://nmap.org )\n"
            "Nmap scan report for 10.20.30.15\n"
            "PORT    STATE SERVICE VERSION\n"
            "22/tcp  open  ssh     OpenSSH 9.6p1 Debian 4\n"
            "443/tcp open  ssl/http nginx 1.24.0\n"
        )
        return 0, stdout, ""

    connector = KaliSSHConnector(
        ssh_config=KaliSSHConfig(host="127.0.0.1", port=2222, username="kali"),
        scope_manager=scope_mgr,
        audit_logger=audit,
        knowledge_base=kb,
        ssh_transport=fake_ssh_transport,
    )

    # 1. Hallucinated flag must be rejected BEFORE SSH dispatch
    bad_flag_res = asyncio.run(
        connector.execute_command("nmap -sV --hallucinated-ai-flag 10.20.30.15")
    )
    assert not bad_flag_res.allowed
    assert bad_flag_res.status_code == 422
    assert bad_flag_res.error_code == "UNKNOWN_TOOL_FLAG"
    assert not bad_flag_res.ssh_dispatched
    assert len(ssh_calls) == 0

    # 2. Out-of-scope target must be blocked BEFORE SSH dispatch
    out_of_scope_res = asyncio.run(
        connector.execute_command("nmap -sV -Pn -p 22,443 8.8.8.8")
    )
    assert not out_of_scope_res.allowed
    assert out_of_scope_res.status_code == 403
    assert out_of_scope_res.error_code == "SCOPE_VIOLATION"
    assert not out_of_scope_res.ssh_dispatched
    assert len(ssh_calls) == 0

    # 3. Shell injection chaining must be blocked BEFORE SSH dispatch
    chained_res = asyncio.run(
        connector.execute_command("nmap -sV 10.20.30.15; id")
    )
    assert not chained_res.allowed
    assert chained_res.status_code == 400
    assert not chained_res.ssh_dispatched
    assert len(ssh_calls) == 0

    # 4. In-scope command with verified --help flags executes over SSH and produces Evidence + Findings
    ok_res = asyncio.run(
        connector.execute_command("nmap -sV -Pn -p 22,443 10.20.30.15")
    )
    assert ok_res.allowed
    assert ok_res.status_code == 200
    assert ok_res.ssh_dispatched
    assert len(ssh_calls) == 1
    assert ok_res.evidence is not None
    assert len(ok_res.findings) == 2
    assert ok_res.help_validation is not None
    assert len(ok_res.help_validation.citations) == 3

    artifact_path = ARTIFACTS_DIR / "phase_l5_kali_ssh_eval.json"
    artifact_path.write_text(
        json.dumps(
            {
                "cached_tools_count": len(tools),
                "cached_tools": tools,
                "hallucinated_flag_blocked_pre_ssh": bad_flag_res.to_dict(),
                "out_of_scope_blocked_pre_ssh": out_of_scope_res.to_dict(),
                "in_scope_ssh_roundtrip": ok_res.to_dict(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


# ============================================================================
# GATE L.6 — REVERSE ENGINEERING TOOLING (AIR-GAPPED + UPLOAD-ONLY + R2 DIFF)
# ============================================================================


def test_gate_l6_re_connector_upload_only_and_crackme_roundtrip(tmp_path: Path) -> None:
    registry = UploadedBinaryRegistry(sandbox_root=tmp_path / "re_airgap")
    re_conn = ReverseEngineeringConnector(registry=registry)

    # 1. Network targets (URLs, IPs) must be blocked with 403 NETWORK_TARGET_FORBIDDEN
    with pytest.raises(ReverseEngineeringRestrictionError) as exc_net:
        re_conn.extract_strings("https://evil.example.com/payload.elf")
    assert exc_net.value.error_code == "NETWORK_TARGET_FORBIDDEN"

    with pytest.raises(ReverseEngineeringRestrictionError) as exc_ip:
        re_conn.static_triage("10.20.30.15")
    assert exc_ip.value.error_code == "NETWORK_TARGET_FORBIDDEN"

    # 2. Unregistered local host file must be blocked with 403 UPLOAD_ONLY_REQUIRED
    unregistered_file = tmp_path / "unregistered.bin"
    unregistered_file.write_bytes(b"\x7fELF_unregistered")
    with pytest.raises(ReverseEngineeringRestrictionError) as exc_unreg:
        re_conn.static_triage(str(unregistered_file))
    assert exc_unreg.value.error_code == "UPLOAD_ONLY_REQUIRED"

    # 3. Upload compiled ELF64 test crackme binary and run full round-trip
    crackme_bytes = build_test_crackme_elf()
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "binaries"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "redloop_crackme.elf").write_bytes(crackme_bytes)

    upload_rec = registry.register_upload(
        content=crackme_bytes,
        filename="redloop_crackme.elf",
        operator_id="alice.sec@redloop.io",
    )

    analysis = re_conn.analyze_uploaded_binary(upload_rec.upload_id)
    r2_cli_ref = re_conn.run_r2_cli_reference(upload_rec.upload_id)

    # Verify 0-diff match between connector output and r2 reference output
    assert analysis["strings"] == r2_cli_ref["izj"]
    assert analysis["functions"] == r2_cli_ref["aflj"]
    assert analysis["disassembly"] == r2_cli_ref["pdfj"]

    extracted_strs = [s["string"] for s in analysis["strings"]]
    assert "FLAG{r2_static_triage_verified_2026}" in extracted_strs
    assert "REDLOOP_CRACKME_V1" in extracted_strs

    fn_names = [f["name"] for f in analysis["functions"]]
    assert "sym.main" in fn_names
    assert "sym.check_serial" in fn_names

    opcodes = [op["opcode"] for op in analysis["disassembly"]["ops"]]
    assert "push rbp" in opcodes
    assert "call sym.check_serial" in opcodes

    # Also verify UPX packer detection on a synthetic UPX-packed buffer
    upx_rec = registry.register_upload(
        content=b"\x7fELF\x02\x01\x01\x00" + b"UPX!" + b"UPX0" + (b"\x90" * 128),
        filename="packed_sample.elf",
    )
    upx_triage = re_conn.static_triage(upx_rec.upload_id)
    assert upx_triage["is_packed"] is True
    assert upx_triage["packer_detected"] == "UPX"

    artifact_path = ARTIFACTS_DIR / "phase_l6_re_eval.json"
    artifact_path.write_text(
        json.dumps(
            {
                "upload_id": upload_rec.upload_id,
                "sha256": upload_rec.sha256,
                "triage": analysis["triage"],
                "strings": analysis["strings"],
                "functions": analysis["functions"],
                "disassembly": analysis["disassembly"],
                "matches_r2_cli_reference": True,
                "upx_packer_detection_verified": upx_triage["packer_detected"] == "UPX",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


# ============================================================================
# GATE L.7 — LOCAL MODEL FLEXIBILITY (NON-OLLAMA OPENAI ENDPOINT + 30 PROMPTS)
# ============================================================================


class _LocalLlamaCppHTTPHandler(BaseHTTPRequestHandler):
    """Lightweight OpenAI-compatible `/v1/chat/completions` & `/v1/models` server (llama.cpp schema)."""

    def log_message(self, format: str, *args: Any) -> None:
        return  # Silence test server stdout noise

    def do_GET(self) -> None:
        if self.path.endswith("/models"):
            body = json.dumps(
                {
                    "object": "list",
                    "data": [
                        {"id": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "object": "model", "owned_by": "llama.cpp"},
                        {"id": "qwen3-4b-instruct-q4_k_m.gguf", "object": "model", "owned_by": "llama.cpp"},
                    ],
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path.endswith("/chat/completions"):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            req = json.loads(raw.decode("utf-8"))
            model = req.get("model", "qwen2.5-0.5b-instruct-q4_k_m.gguf")
            messages = req.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            reply = f"[llama.cpp:{model}] Grounded analysis for: {user_msg[:80]}"
            resp_obj = {
                "id": "chatcmpl-llamacpp-l7",
                "object": "chat.completion",
                "created": 1762840000,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": reply},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": len(user_msg.split()) + 8,
                    "completion_tokens": len(reply.split()),
                    "total_tokens": len(user_msg.split()) + len(reply.split()) + 8,
                },
            }
            body = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def test_gate_l7_local_openai_ram_tiering_and_30_prompt_benchmark() -> None:
    # 1. Verify Phase C RAM tiering on non-Ollama GGUF models
    tiered_low, warn_low = select_resource_aware_local_openai_model(
        "qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        safe_ram_threshold_gb=6.0,
        total_ram_override=8.0,
        avail_ram_override=1.8,
    )
    assert tiered_low == "qwen2.5-0.5b-instruct-q4_k_m.gguf"
    assert warn_low is not None and "RESOURCE WARNING" in warn_low

    tiered_mid, warn_mid = select_resource_aware_local_openai_model(
        "llama-3.1-8b-instruct-q4_k_m.gguf",
        safe_ram_threshold_gb=6.0,
        total_ram_override=16.0,
        avail_ram_override=4.2,
    )
    assert tiered_mid == "qwen3-4b-instruct-q4_k_m.gguf"
    assert warn_mid is not None

    # 2. Start live local OpenAI-compatible server (llama.cpp protocol) on an ephemeral loopback port
    server = HTTPServer(("127.0.0.1", 0), _LocalLlamaCppHTTPHandler)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}/v1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Verify LLMSettings + LLMClient unified configuration path
        settings = LLMSettings(
            llm_provider="local_openai",
            local_openai_base_url=base_url,
            local_openai_model="qwen2.5-coder-7b-instruct-q4_k_m.gguf",
            ollama_safe_ram_threshold_gb=6.0,
        )
        llm_client = LLMClient(settings=settings)
        assert llm_client.default_provider == Provider.LOCAL_OPENAI
        single_res = llm_client.complete(
            system_prompt="You are REDLOOP.",
            user_prompt="Verify local_openai config path.",
        )
        assert single_res["provider"] == "local_openai"
        assert "[llama.cpp:" in single_res["text"]

        # Run the full 30-prompt benchmark against the non-Ollama local OpenAI endpoint
        cfg = LocalOpenAIEndpointConfig(
            base_url=base_url,
            backend_type="llama_cpp",
            requested_model="qwen2.5-coder-7b-instruct-q4_k_m.gguf",
            safe_ram_threshold_gb=6.0,
        )
        adapter_client = LocalOpenAIClient(config=cfg)
        models = adapter_client.list_models()
        assert "qwen2.5-0.5b-instruct-q4_k_m.gguf" in models

        bench_report = run_local_openai_30_prompt_benchmark(
            adapter_client,
            prompts=BENCHMARK_30_PROMPTS,
        )
        assert bench_report["total_prompts"] == 30
        assert bench_report["completed_prompts"] == 30
        assert bench_report["failed_prompts"] == 0
        assert bench_report["oom_count"] == 0

        artifact_path = ARTIFACTS_DIR / "phase_l7_local_model_benchmark.json"
        artifact_path.write_text(json.dumps(bench_report, indent=2) + "\n", encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()
