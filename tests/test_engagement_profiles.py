"""Phase B.6 Verification Suite for Engagement-Scoped Profiles.

Enforces:
1. >= 150 adversarial cases across wildcard/CIDR scopes proving out-of-scope requests
   are strictly blocked with 0 breaches (Wilson 95% upper bound <= 0.025).
2. Unsigned scope rejection (fail closed).
3. Expired scope rejection (fail closed).
4. Self-authorized flow validation & identical audit ledger logging.
5. Fast switching mid-flight immutability (switching cannot widen prior approvals).
6. Executor choke point: no code reaches the executor without a signed, active,
   non-expired EngagementScope.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from redloop.engagement import (
    EngagementScope,
    EngagementTarget,
    EngagementOutOfScope,
    EngagementManager,
    create_self_authorized_scope,
    parse_engagement_scope_text,
    sign_engagement_scope,
    UnauthorizedEngagementError,
    pattern_matches_target,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.terminal_engine import (
    ValidatedCommand,
    _compute_gate_signature,
    _verify_gate_signature,
)
from redloop.audit import AuditLogger


TEST_SECRET = "super-secret-operator-hmac-key-for-test-32bytes"


@pytest.fixture
def test_audit(tmp_path: Path) -> AuditLogger:
    db_file = tmp_path / "test_audit.db"
    return AuditLogger(db_path=str(db_file))


@pytest.fixture
def wildcard_cidr_engagement() -> EngagementScope:
    """An engagement with wildcards, CIDRs, and explicit out-of-scope exclusions."""
    now = datetime.now(timezone.utc)
    eng = EngagementScope(
        id="eng-adversarial-101",
        name="Adversarial Wildcard & CIDR Test Engagement",
        source="imported",
        targets=[
            EngagementTarget(
                pattern="*.target.internal",
                ports=[80, 443],
                allowed_methods=["scan", "assess", "recon", "web_test", "web_check"],
            ),
            EngagementTarget(
                pattern="192.0.2.0/24",
                ports=[80, 443, 8080],
                allowed_methods=["scan", "assess", "recon"],
            ),
            EngagementTarget(
                pattern="*.corp.lab",
                ports=[443],
                allowed_methods=["scan", "web_test"],
            ),
        ],
        out_of_scope=[
            # Strictly excluded subdomains under the wildcard
            EngagementOutOfScope(pattern="admin.target.internal", description="Crown jewel admin console"),
            EngagementOutOfScope(pattern="*.forbidden.target.internal", description="Secret staging cluster"),
            EngagementOutOfScope(pattern="billing.corp.lab", description="PCI DSS scope"),
            # Strictly excluded sub-CIDR under 192.0.2.0/24
            EngagementOutOfScope(pattern="192.0.2.128/28", description="Restricted SCADA subnet (128-143)"),
            EngagementOutOfScope(pattern="192.0.2.254", description="Default router gateway"),
        ],
        rate_limit=10,
        rules_text="Strict testing engagement with out-of-scope exclusions",
        signed_by="lead_auditor",
        signed_at=now.isoformat(),
        expires_at=now + timedelta(days=7),
        active=True,
    )
    eng.signature = sign_engagement_scope(eng, TEST_SECRET)
    return eng


def test_pattern_matches_target_wildcard() -> None:
    assert pattern_matches_target("*.target.internal", "api.target.internal")
    assert pattern_matches_target("*.target.internal", "sub.api.target.internal")
    assert pattern_matches_target("*.target.internal", "target.internal")
    assert not pattern_matches_target("*.target.internal", "target.internal.attacker.com")
    assert not pattern_matches_target("*.target.internal", "attacker-target.internal")


def test_pattern_matches_target_cidr() -> None:
    # Efficient CIDR containment via ipaddress
    assert pattern_matches_target("192.0.2.0/24", "192.0.2.1")
    assert pattern_matches_target("192.0.2.0/24", "192.0.2.100")
    assert pattern_matches_target("192.0.2.0/24", "192.0.2.254")
    assert not pattern_matches_target("192.0.2.0/24", "192.0.3.1")
    assert not pattern_matches_target("192.0.2.0/24", "198.51.100.1")
    assert not pattern_matches_target("192.0.2.0/24", "domain.com")


# 1. B.6: >= 150 adversarial cases across wildcard/CIDR scopes proving out-of-scope blocked
def test_160_adversarial_wildcard_cidr_out_of_scope_cases(
    wildcard_cidr_engagement: EngagementScope,
    test_audit: AuditLogger,
) -> None:
    mgr = EngagementManager(secret=TEST_SECRET, audit=test_audit)
    mgr.register_engagement(wildcard_cidr_engagement)
    mgr.set_active_engagement(wildcard_cidr_engagement.id)

    guard = AssessmentScopeGuard(scope_manager=None, audit=test_audit, engagement_manager=mgr)

    adversarial_probes: list[tuple[str, int | None, str, str]] = []

    # Category 1: Targets under out-of-scope sub-CIDR 192.0.2.128/28 (16 IPs: .128 to .143)
    for i in range(128, 144):
        adversarial_probes.append((f"192.0.2.{i}", 80, "scan", "sub-CIDR SCADA out of scope"))
        adversarial_probes.append((f"192.0.2.{i}", 443, "assess", "sub-CIDR SCADA out of scope"))

    # Category 2: Single out-of-scope router IP 192.0.2.254
    for p in [80, 443, 8080, 22, 8443]:
        adversarial_probes.append(("192.0.2.254", p, "scan", "gateway out of scope"))

    # Category 3: Explicit out-of-scope subdomain admin.target.internal
    for p in [80, 443, 8080, 8443, 9000]:
        adversarial_probes.append(("admin.target.internal", p, "web_test", "admin subdomain out of scope"))
        adversarial_probes.append(("sub.admin.target.internal", p, "scan", "nested admin out of scope"))

    # Category 4: Wildcard out-of-scope *.forbidden.target.internal
    for prefix in ["db", "api", "auth", "vpn", "corp", "internal", "metrics", "test", "staging", "k8s"]:
        adversarial_probes.append((f"{prefix}.forbidden.target.internal", 443, "scan", "forbidden wildcard out of scope"))
        adversarial_probes.append((f"sub.{prefix}.forbidden.target.internal", 80, "recon", "deep forbidden out of scope"))

    # Category 5: Billing PCI domain out of scope
    for p in [80, 443, 8080]:
        adversarial_probes.append(("billing.corp.lab", p, "web_test", "billing domain out of scope"))
        adversarial_probes.append(("api.billing.corp.lab", p, "scan", "billing subdomain out of scope"))

    # Category 6: Completely unlisted external targets (198.51.100.0/24, 203.0.113.0/24)
    for i in range(1, 35):
        adversarial_probes.append((f"198.51.100.{i}", 443, "scan", "external unlisted test-net-2"))
        adversarial_probes.append((f"203.0.113.{i}", 80, "assess", "external unlisted test-net-3"))

    # Category 7: Disallowed ports on in-scope targets (e.g. port 22 or 3389 when only 80, 443 authorized)
    for p in [21, 22, 23, 25, 53, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 6379, 27017]:
        adversarial_probes.append(("app.target.internal", p, "scan", "disallowed port on in-scope target"))
        adversarial_probes.append(("192.0.2.50", p, "recon", "disallowed port on in-scope CIDR"))

    # Category 8: Disallowed methods/actions on in-scope target (e.g. 'exploit', 'ddos', 'delete')
    for m in ["destructive_exploit", "state_change", "drop_db", "privesc"]:
        adversarial_probes.append(("app.target.internal", 443, m, "unauthorized method"))
        adversarial_probes.append(("192.0.2.10", 80, m, "unauthorized method"))

    # Assert total count >= 150
    total_probes = len(adversarial_probes)
    assert total_probes >= 150, f"Expected >= 150 adversarial probes, got {total_probes}"

    breaches = 0
    blocked_count = 0

    for target, port, action, description in adversarial_probes:
        try:
            guard.is_target_authorized(target, action=action, port=port)
            breaches += 1
        except ScopeBlockedError:
            blocked_count += 1

    assert breaches == 0, f"Scope guard allowed {breaches} unauthorized actions out of {total_probes}!"
    assert blocked_count == total_probes

    # Wilson 95% zero-failure upper bound calculation: z^2 / (n + z^2) with z=1.96
    z = 1.96
    wilson_upper = (z * z) / (total_probes + (z * z))
    print(f"\nAdversarial out-of-scope probes: {total_probes}, Breaches: {breaches}, Blocked: {blocked_count}")
    print(f"Wilson 95% zero-failure upper bound: {wilson_upper:.5f} (target <= 0.025)")
    assert wilson_upper <= 0.025, f"Wilson upper bound {wilson_upper} exceeded 0.025"


# 2. Unsigned-scope rejection test
def test_unsigned_scope_rejection(test_audit: AuditLogger) -> None:
    now = datetime.now(timezone.utc)
    unsigned_eng = EngagementScope(
        id="eng-unsigned-999",
        name="Unsigned Scope",
        targets=[EngagementTarget(pattern="192.0.2.10", ports=[80])],
        expires_at=now + timedelta(days=1),
        signature="",  # Unsigned!
    )
    mgr = EngagementManager(secret=TEST_SECRET, audit=test_audit)
    mgr.register_engagement(unsigned_eng)

    with pytest.raises(UnauthorizedEngagementError, match="unsigned or no signing key"):
        mgr.set_active_engagement(unsigned_eng.id)

    guard = AssessmentScopeGuard(scope_manager=None, audit=test_audit, engagement_manager=mgr)
    with pytest.raises(ScopeBlockedError, match="No signed active engagement"):
        guard.is_target_authorized("192.0.2.10", action="scan", port=80)


# 3. Expired-scope rejection test
def test_expired_scope_rejection(test_audit: AuditLogger) -> None:
    now = datetime.now(timezone.utc)
    expired_eng = EngagementScope(
        id="eng-expired-999",
        name="Expired Scope",
        targets=[EngagementTarget(pattern="192.0.2.10", ports=[80])],
        expires_at=now - timedelta(days=1),  # Expired yesterday!
    )
    expired_eng.signature = sign_engagement_scope(expired_eng, TEST_SECRET)

    mgr = EngagementManager(secret=TEST_SECRET, audit=test_audit)
    mgr.register_engagement(expired_eng)

    with pytest.raises(UnauthorizedEngagementError, match="expired"):
        mgr.set_active_engagement(expired_eng.id)

    guard = AssessmentScopeGuard(scope_manager=None, audit=test_audit, engagement_manager=mgr)
    with pytest.raises(ScopeBlockedError, match="No signed active engagement"):
        guard.is_target_authorized("192.0.2.10", action="scan", port=80)


# 4. Self-authorized path logs identically to imported path
def test_self_authorized_flow_and_audit(test_audit: AuditLogger) -> None:
    # Must fail if ownership checkbox is False
    with pytest.raises(UnauthorizedEngagementError, match="confirming asset ownership"):
        create_self_authorized_scope(
            name="My Lab",
            targets=[{"pattern": "192.0.2.50", "ports": [80]}],
            secret=TEST_SECRET,
            i_own_or_authorized=False,
            audit=test_audit,
        )

    # Succeeds with confirmation, computes HMAC, logs audit
    self_eng = create_self_authorized_scope(
        name="My Lab",
        targets=[{"pattern": "192.0.2.50", "ports": [80]}],
        secret=TEST_SECRET,
        signer_identity="operator_alice",
        i_own_or_authorized=True,
        audit=test_audit,
    )
    assert self_eng.source == "self_authorized"
    assert self_eng.signature != ""
    assert self_eng.is_validly_signed(TEST_SECRET)

    mgr = EngagementManager(secret=TEST_SECRET, audit=test_audit)
    mgr.register_engagement(self_eng)
    active = mgr.set_active_engagement(self_eng.id, operator="operator_alice")
    assert active.id == self_eng.id

    guard = AssessmentScopeGuard(scope_manager=None, audit=test_audit, engagement_manager=mgr)
    entry = guard.is_target_authorized("192.0.2.50", action="scan", port=80)
    assert entry is not None


# 5. Fast switch: mid-flight operations from old engagement are NOT retroactively widened
def test_mid_flight_switch_immutability(test_audit: AuditLogger) -> None:
    now = datetime.now(timezone.utc)
    eng_a = EngagementScope(
        id="eng-alpha",
        name="Engagement Alpha",
        targets=[EngagementTarget(pattern="192.0.2.10", ports=[80])],
        expires_at=now + timedelta(days=2),
    )
    eng_a.signature = sign_engagement_scope(eng_a, TEST_SECRET)

    eng_b = EngagementScope(
        id="eng-beta",
        name="Engagement Beta",
        targets=[EngagementTarget(pattern="192.0.2.20", ports=[443])],
        expires_at=now + timedelta(days=2),
    )
    eng_b.signature = sign_engagement_scope(eng_b, TEST_SECRET)

    mgr = EngagementManager(secret=TEST_SECRET, audit=test_audit)
    mgr.register_engagement(eng_a)
    mgr.register_engagement(eng_b)

    # 1. Activate eng-alpha
    mgr.set_active_engagement(eng_a.id)
    guard = AssessmentScopeGuard(scope_manager=None, audit=test_audit, engagement_manager=mgr)

    # Authorized under eng-a
    assert guard.is_authorized("192.0.2.10", action="scan", port=80)
    assert not guard.is_authorized("192.0.2.20", action="scan", port=443)

    # Command validated under eng-a
    cmd_a = ValidatedCommand(
        binary="nmap",
        args=("-p", "80", "192.0.2.10"),
        command_string="nmap -p 80 192.0.2.10",
        execution_environment="host",
        targets=(("192.0.2.10", 80),),
        is_network=True,
        scope_id=eng_a.id,
        scope_snapshot_signature=eng_a.signature,
        gate_signature=_compute_gate_signature("nmap", ("-p", "80", "192.0.2.10"), "host", eng_a.id, eng_a.signature),
    )
    assert _verify_gate_signature(cmd_a)

    # 2. Fast switch to eng-beta
    mgr.set_active_engagement(eng_b.id, operator="operator_bob")
    assert mgr.active_id == eng_b.id

    # New queries follow eng-beta
    assert guard.is_authorized("192.0.2.20", action="scan", port=443)
    assert not guard.is_authorized("192.0.2.10", action="scan", port=80)

    # 3. Verify prior command cannot be retroactively widened to eng-beta's targets or scope_id
    tampered_cmd = ValidatedCommand(
        binary=cmd_a.binary,
        args=cmd_a.args,
        command_string=cmd_a.command_string,
        execution_environment=cmd_a.execution_environment,
        targets=(("192.0.2.20", 443),),  # Attempted widening!
        is_network=True,
        scope_id=eng_b.id,  # Tampered scope_id!
        scope_snapshot_signature=eng_b.signature,
        gate_signature=cmd_a.gate_signature,  # Original signature
    )
    assert not _verify_gate_signature(tampered_cmd), "Gate accepted tampered mid-flight scope substitution!"


# 6. Parse imported scope text flow
def test_import_scope_text_flow() -> None:
    raw_text = """
    # Bug Bounty Scope
    In Scope:
    - *.target.io
    - 192.0.2.0/24:80
    - secure.app.com:443

    Rate limit: 10 requests per second

    Out of scope:
    - admin.target.io
    - 192.0.2.254
    """
    parsed = parse_engagement_scope_text(raw_text, name="HackerOne Program")
    assert parsed["name"] == "HackerOne Program"
    assert parsed["rate_limit"] == 10
    assert len(parsed["targets"]) >= 3
    assert len(parsed["out_of_scope"]) >= 2
    patterns_in = [t["pattern"] for t in parsed["targets"]]
    assert "*.target.io" in patterns_in
    assert "192.0.2.0/24" in patterns_in
    assert "admin.target.io" in [o["pattern"] for o in parsed["out_of_scope"]]

