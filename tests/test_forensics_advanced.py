"""Unit tests for Advanced Forensics Engine (Event logs, auth logs, entropy, IOC extraction)."""

import pytest
from redloop.forensics_advanced import get_advanced_forensics_engine


def test_windows_event_log_4625_triage():
    engine = get_advanced_forensics_engine()
    raw_evtx_text = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-10-26T12:00:00.000Z"/>
      </System>
      <EventData>
        <Data Name="TargetUserName">Administrator</Data>
        <Data Name="IpAddress">192.168.1.150</Data>
        <Data Name="FailureReason">Unknown user name or bad password</Data>
      </EventData>
    </Event>
    """
    res = engine.triage_log("windows_event", raw_evtx_text)
    assert res["log_type"] == "windows_event"
    assert len(res["findings"]) >= 1
    f = res["findings"][0]
    assert f["event_id"] == 4625
    assert f["severity"] in ("HIGH", "CRITICAL")
    assert f["target_user"] == "Administrator"
    assert "T1110" in f["mitre_technique"]  # Brute Force


def test_linux_auth_log_triage():
    engine = get_advanced_forensics_engine()
    raw_auth_log = """
    Oct 26 12:00:01 kali sshd[1234]: Failed password for root from 192.168.1.200 port 4567 ssh2
    Oct 26 12:00:03 kali sshd[1235]: Failed password for invalid user oracle from 192.168.1.200 port 4568 ssh2
    """
    res = engine.triage_log("linux_auth", raw_auth_log)
    assert res["log_type"] == "linux_auth"
    assert len(res["findings"]) >= 1
    assert any("root" in str(f) for f in res["findings"])


def test_shannon_entropy_calculation():
    engine = get_advanced_forensics_engine()
    # High entropy random payload vs low entropy repetitive text
    low_entropy_bytes = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    high_entropy_bytes = b"\x8f\x3a\x91\xb4\x01\xfe\xca\x99\x12\x45\x77\xaa\xbc\xde\xef\x00\x55\x33\x11"

    ent_low = engine.calculate_entropy(low_entropy_bytes)
    ent_high = engine.calculate_entropy(high_entropy_bytes)

    assert ent_low < 1.0
    assert ent_high > 3.0


def test_ioc_extraction_with_mitre_mapping():
    engine = get_advanced_forensics_engine()
    text = (
        "Attacker accessed C2 IP 198.51.100.45 and dropped malware with SHA256 "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
        "Communicated with malicious domain badsite.test."
    )
    res = engine.extract_iocs(text)
    assert "198.51.100.45" in res["ips"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in res["sha256_hashes"]
    assert len(res["mitre_techniques"]) > 0
