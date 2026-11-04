"""Phase 7 SOAR Action Registry Automated Verification Suite.

Covers:
1. Typed action execution (Investigation, Defensive, Containment, Notification).
2. Indicator enrichment for IP and hash.
3. Local firewall blocklist simulation (explicitly flagged SIMULATED).
4. Unconfigured EDR / Identity provider handling (returning NOT_CONFIGURED or SIMULATED).
5. SSRF validation: Rejecting private IPs, loopback, link-local, and non-HTTPS webhooks.
"""

from __future__ import annotations

import pytest

from redloop.assessment.soar_actions import (
    ActionCategory,
    ActionExecutionStatus,
    SOARActionRegistry,
    SSRFValidationError,
    SafeWebhookClient,
)
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)


def test_01_retrieve_related_events_action():
    """Retrieves matched events for target IP or host."""
    ev1 = UniversalSecurityEvent(
        event_id="e-act-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="web_access",
        source_file="access.log",
        event_category=EventCategory.WEB,
        event_action="http_request",
        severity=EventSeverity.MEDIUM,
        source_ip="192.168.1.50",
    )
    ev2 = UniversalSecurityEvent(
        event_id="e-act-2",
        timestamp="2026-11-04T12:01:00Z",
        ingestion_timestamp="2026-11-04T12:01:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.LOW,
        source_ip="10.0.0.1",
    )

    res = SOARActionRegistry.retrieve_related_events(
        target_ip="192.168.1.50",
        stored_events=[ev1, ev2],
    )
    assert res.status == ActionExecutionStatus.SUCCESS
    assert res.output_data["matched_count"] == 1
    assert res.evidence_ids == ["e-act-1"]


def test_02_enrich_indicator_ip_and_hash():
    """Enriches IP and SHA-256 hash indicators."""
    res_ip = SOARActionRegistry.enrich_indicator("192.168.1.1", indicator_type="ip")
    assert res_ip.status == ActionExecutionStatus.SUCCESS
    assert res_ip.output_data["reputation"] == "INTERNAL_PRIVATE_IP"

    res_hash = SOARActionRegistry.enrich_indicator("a" * 64, indicator_type="hash")
    assert res_hash.status == ActionExecutionStatus.SUCCESS
    assert res_hash.output_data["reputation"] == "SUSPICIOUS_HASH"


def test_03_simulate_indicator_blocklist_flagged_simulated():
    """Simulated local blocklist is strictly labeled SIMULATED and is_simulated=True."""
    res = SOARActionRegistry.simulate_indicator_blocklist("203.0.113.5", reason="C2 communication")
    assert res.status == ActionExecutionStatus.SIMULATED
    assert res.is_simulated is True
    assert "SIMULATED" in res.details


def test_04_unconfigured_provider_handling():
    """Unconfigured EDR provider returns NOT_CONFIGURED when simulate_if_unconfigured is False."""
    res = SOARActionRegistry.isolate_endpoint(
        host_ip="192.168.1.50",
        provider="crowdstrike_falcon",
        capability_token="valid-token",
        simulate_if_unconfigured=False,
    )
    assert res.status == ActionExecutionStatus.NOT_CONFIGURED
    assert "not configured" in res.details.lower()


def test_05_ssrf_webhook_protection_blocks_internal_and_loopback():
    """SSRF filter strictly rejects private IPs, loopback, AWS metadata, and non-HTTPS endpoints."""
    # Loopback
    with pytest.raises(SSRFValidationError):
        SafeWebhookClient.validate_url("https://127.0.0.1:8443/alert")

    # Localhost
    with pytest.raises(SSRFValidationError):
        SafeWebhookClient.validate_url("https://localhost:9000/hook")

    # AWS metadata service IP
    with pytest.raises(SSRFValidationError):
        SafeWebhookClient.validate_url("https://169.254.169.254/latest/meta-data")

    # Plain HTTP (must be HTTPS)
    with pytest.raises(SSRFValidationError):
        SafeWebhookClient.validate_url("http://example.com/webhook")

    # send_webhook_notification action returns BLOCKED
    res = SOARActionRegistry.send_webhook_notification(
        webhook_url="https://127.0.0.1/notify",
        message="Test alert",
    )
    assert res.status == ActionExecutionStatus.BLOCKED
    assert "SSRF Protection" in res.details
