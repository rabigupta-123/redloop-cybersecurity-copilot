"""Unit and integration tests for V11 Mathematical Security Analytics and Copilot Integrity."""

import pytest
import math
import httpx
from datetime import datetime, timezone, timedelta

from redloop.assessment.attack_reconstruction import (
    calculate_shannon_entropy,
    calculate_normalized_entropy,
    calculate_bounded_graph_risk,
)
from redloop.assessment.ioc_engine import IOCRecord, IOCType, IOCState


class TestMathematicalSecurityAnalytics:
    def test_shannon_entropy_properties(self):
        # Empty string has 0.0 entropy
        assert calculate_shannon_entropy("") == 0.0
        # Single repeated character has 0.0 entropy
        assert calculate_shannon_entropy("AAAAAAA") == 0.0
        # String with 2 equiprobable chars has exactly 1.0 bit/char
        h2 = calculate_shannon_entropy("ABABABAB")
        assert math.isclose(h2, 1.0, abs_tol=0.01)
        # Standard command line typically has 2.0 - 4.0 bits
        cmd_h = calculate_shannon_entropy("whoami /user")
        assert 2.0 <= cmd_h <= 4.0
        # High diversity characters string exhibits entropy >= 4.5
        high_h = calculate_shannon_entropy("1a2b3c4d5e6f7g8h9i0j!@#$%^&*()_+~QWERTYUIOPASDFGHJKLZXCVBNM")
        assert high_h >= 4.5

    def test_normalized_entropy_properties(self):
        # Empty string returns 0.0
        assert calculate_normalized_entropy("") == 0.0
        # Single unique character returns 0.0
        assert calculate_normalized_entropy("AAAAAA") == 0.0
        # Equiprobable distribution with all unique characters should give normalized entropy ~ 1.0
        all_unique = "abcdefghijklmnopqrstuvwxyz"
        assert math.isclose(calculate_normalized_entropy(all_unique), 1.0, abs_tol=0.01)
        # Any string normalized entropy must remain strictly bounded in [0.0, 1.0]
        test_strings = [
            "powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
            "cat /etc/passwd",
            "1234567890",
            "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB",
        ]
        for s in test_strings:
            norm_h = calculate_normalized_entropy(s)
            assert 0.0 <= norm_h <= 1.0

    def test_bounded_attack_graph_risk(self):
        # Zero risk
        assert calculate_bounded_graph_risk(0, 0, 0, 0) == 0.0
        # Sub-threshold risk
        r1 = calculate_bounded_graph_risk(nodes_count=2, critical_indicators=0, high_indicators=1, medium_indicators=1)
        assert r1 == 30.0
        # Over-threshold risk must be strictly clamped to 100.0
        r_overflow = calculate_bounded_graph_risk(
            nodes_count=10,
            critical_indicators=5,
            high_indicators=5,
            medium_indicators=5,
            has_lolbin=True,
            has_high_entropy=True,
        )
        assert r_overflow == 100.0
        assert 0.0 <= r_overflow <= 100.0

    def test_ioc_exponential_decay(self):
        now = datetime.now(timezone.utc)
        # Indicator seen right now: decayed confidence equals initial confidence
        ioc_fresh = IOCRecord(
            ioc_id="ioc-1",
            ioc_type=IOCType.IP,
            value="198.51.100.4",
            state=IOCState.CONFIRMED_MALICIOUS,
            source="threat-feed",
            confidence=0.8,
            reputation="MALICIOUS",
            first_seen=now.isoformat(),
            last_seen=now.isoformat(),
        )
        assert math.isclose(ioc_fresh.calculate_decayed_confidence(half_life_days=30.0), 0.8, abs_tol=0.02)

        # Indicator seen 30 days ago with 30-day half-life: decayed confidence should be approx C_0 / 2
        past_30d = (now - timedelta(days=30.0)).isoformat()
        ioc_old = IOCRecord(
            ioc_id="ioc-2",
            ioc_type=IOCType.DOMAIN,
            value="evil-domain.example",
            state=IOCState.CONFIRMED_MALICIOUS,
            source="threat-feed",
            confidence=0.8,
            reputation="MALICIOUS",
            first_seen=past_30d,
            last_seen=past_30d,
        )
        decayed_30 = ioc_old.calculate_decayed_confidence(half_life_days=30.0)
        assert math.isclose(decayed_30, 0.4, abs_tol=0.03)

        # Indicator seen 60 days ago: approx C_0 / 4
        past_60d = (now - timedelta(days=60.0)).isoformat()
        ioc_older = IOCRecord(
            ioc_id="ioc-3",
            ioc_type=IOCType.HASH,
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            state=IOCState.CONFIRMED_MALICIOUS,
            source="threat-feed",
            confidence=0.8,
            reputation="MALICIOUS",
            first_seen=past_60d,
            last_seen=past_60d,
        )
        decayed_60 = ioc_older.calculate_decayed_confidence(half_life_days=30.0)
        assert math.isclose(decayed_60, 0.2, abs_tol=0.03)


class TestSOCDashboardSummaryAPI:
    def test_get_soc_dashboard_summary_schema(self):
        with httpx.Client(base_url="http://127.0.0.1:8765", timeout=10.0) as client:
            resp = client.get("/api/soc/dashboard/summary")
            assert resp.status_code == 200
            data = resp.json()

            # Check Row 1 KPIs
            assert "kpis" in data
            k = data["kpis"]
            assert "total_alerts" in k
            assert "critical_high_alerts" in k
            assert "active_incidents" in k
            assert "active_investigations" in k
            assert "connected_integrations" in k
            assert "risk_posture_score" in k
            assert 0.0 <= k["risk_posture_score"] <= 100.0
            assert k["risk_posture_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

            # Check Row 2 Analytics
            assert "analytics" in data
            a = data["analytics"]
            assert "alert_trend" in a
            assert isinstance(a["alert_trend"], list)
            assert "threat_intel" in a
            assert "risk_trend" in a
            assert "soc_health" in a
            health = a["soc_health"]
            assert "mttd_status" in health
            assert "mttr_status" in health
            assert "sync_status" in health
            assert health["reduction_status"] == "UNSUPPORTED"

            # Check Row 3 Workspace
            assert "workspace" in data
            w = data["workspace"]
            assert "incidents" in w
            assert "investigations" in w
            assert "detections" in w
            assert "integrations" in w

            # Check Row 4 Activity
            assert "activity" in data
            act = data["activity"]
            assert "recent_audit" in act
            assert "evidence_status" in act
            assert "soar_history" in act


class TestCopilotResponseIntegrity:
    def test_copilot_deterministic_and_audit(self):
        with httpx.Client(base_url="http://127.0.0.1:8765", timeout=15.0) as client:
            # 1. DNS question triggers DNS fundamentals
            resp_dns = client.post("/api/chat", json={"message": "explain how dns works"})
            assert resp_dns.status_code == 200
            d_dns = resp_dns.json()
            assert "DNS" in d_dns["response"]
            assert d_dns.get("audit_event_id") != ""

            # 2. TCP question triggers TCP fundamentals
            resp_tcp = client.post("/api/chat", json={"message": "explain tcp three-way handshake"})
            assert resp_tcp.status_code == 200
            d_tcp = resp_tcp.json()
            assert "TCP" in d_tcp["response"]
            assert d_tcp.get("audit_event_id") != ""
