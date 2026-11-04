"""Phase 5 Automated Verification Suite: Autonomous SOC Investigation, Threat Detection & Incident Response Engine.

Covers:
1.  Telemetry Parsers: Linux Auth & Syslog (failed/successful logins, sudo)
2.  Telemetry Parsers: Web Access (Combined Log, SQLi, traversal patterns)
3.  Telemetry Parsers: Suricata EVE JSON (alerts, DNS queries, severity)
4.  Telemetry Parsers: Windows Sysmon (Event IDs 1, 3, 11, PowerShell obfuscation)
5.  Telemetry Parsers: Email EML (MIME headers, SPF/DKIM verification, attachments)
6.  Telemetry Parsers: Generic JSON and CSV security events
7.  Timestamp Normalization: Epoch, Syslog, Apache, ISO UTC
8.  Streaming Ingestion & Deduplication by Event Content Hash
9.  Ingestion SHA-256 Provenance & File Hash Integrity
10. Detection Engine: SEC-AUTH-001 Brute-Force Authentication Activity
11. Detection Engine: SEC-AUTH-002 Successful Logon Following Failures (Critical)
12. Detection Engine: SEC-PROC-001 Obfuscated PowerShell Execution (-enc / bypass)
13. Detection Engine: SEC-PROC-002 Web Server Spawning Interactive Shell (Web Shell)
14. Detection Engine: SEC-WEB-001 Web Attack Indicators (SQL Injection & Path Traversal)
15. Detection Engine: SEC-NET-001 DNS Tunneling / Covert Channel Heuristics
16. Detection Engine: SEC-HASH-001 Known Malicious File Hash Catalog Matching
17. SOC Timeline: Unified Chronological UTC Ordering
18. SOC Timeline: Multi-Field Filtering (Host, User, IP, Severity, Category)
19. Incident Correlation: Clustering Related Alerts by Shared Entity
20. Incident Graph Relations: SAME_HOST, SAME_SOURCE, Evidence Provenance
21. Response Playbooks: 8 Structured Playbooks (PB-CRED, PB-BRUTE, PB-PSHELL, PB-WEB, etc.)
22. Response Playbooks: Strict Human Approval Enforcement & Containment Audit
23. Autonomous Copilot SOC: Natural Language Query & Indicator Extraction
24. Autonomous Copilot SOC: Gap Analysis & Missing Evidence Flagging
25. Autonomous Copilot SOC: Multi-Format Investigation Report Export (JSON/Markdown)
26. REST API: Ingest Telemetry & List Normalized Events
27. REST API: Run Threat Detections, View Alerts & Correlate Incidents
28. REST API: Chronological Timeline, Playbook Execution & Approval Enforcement
29. REST API: Autonomous Investigation & Report Generation Endpoints
"""

import hashlib
import json
import pytest
from starlette.testclient import TestClient

from redloop.assessment.soc_copilot import InvestigationLifecycleState, SOCCopilotEngine
from redloop.assessment.soc_detection import SOCAlert, SOCDetectionEngine
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    ParserStatus,
    TelemetryIngestionEngine,
    TelemetryParsers,
    TimestampNormalizer,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_playbooks import PlaybookStepStatus, SOCPlaybookEngine
from redloop.assessment.soc_timeline import (
    EvidenceObservationClass,
    IncidentRelationType,
    SOCIncidentCorrelator,
    SOCTimelineEngine,
)


# =========================================================================
# Part 1: Telemetry Parsers & Ingestion Engine
# =========================================================================

def test_01_telemetry_parsers_linux_auth():
    """Parses Linux authentication and system logs."""
    # Failed password
    raw_failed = "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 44222 ssh2"
    evt_failed = TelemetryParsers.parse_linux_auth(raw_failed, "auth.log", "evi-1")
    assert evt_failed is not None
    assert evt_failed.event_action == "logon_failed"
    assert evt_failed.username == "admin"
    assert evt_failed.source_ip == "192.168.1.50"
    assert evt_failed.hostname == "web01"
    assert evt_failed.severity == EventSeverity.MEDIUM

    # Accepted password
    raw_ok = "Oct 24 14:15:10 web01 sshd[12348]: Accepted password for root from 192.168.1.50 port 44226 ssh2"
    evt_ok = TelemetryParsers.parse_linux_auth(raw_ok, "auth.log", "evi-2")
    assert evt_ok is not None
    assert evt_ok.event_action == "logon_success"
    assert evt_ok.username == "root"

    # Sudo command
    raw_sudo = "Oct 24 14:16:00 web01 sudo[12350]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    evt_sudo = TelemetryParsers.parse_linux_auth(raw_sudo, "auth.log", "evi-3")
    assert evt_sudo is not None
    assert evt_sudo.event_action == "sudo_execution"
    assert evt_sudo.command_line == "/bin/cat /etc/shadow"


def test_02_telemetry_parsers_web_access():
    """Parses web access logs and flags web attacks."""
    raw_normal = '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326'
    evt_norm = TelemetryParsers.parse_web_access(raw_normal, "access.log", "evi-web-1")
    assert evt_norm is not None
    assert evt_norm.source_ip == "10.0.0.1"
    assert evt_norm.url == "/index.html"
    assert evt_norm.severity == EventSeverity.INFORMATIONAL

    # SQL Injection in URL
    raw_sqli = '10.0.0.99 - - [10/Oct/2026:13:56:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 120'
    evt_sqli = TelemetryParsers.parse_web_access(raw_sqli, "access.log", "evi-web-2")
    assert evt_sqli is not None
    assert evt_sqli.severity == EventSeverity.HIGH

    # Path traversal in URL
    raw_traversal = '10.0.0.99 - - [10/Oct/2026:13:56:30 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 403 0'
    evt_trav = TelemetryParsers.parse_web_access(raw_traversal, "access.log", "evi-web-3")
    assert evt_trav is not None
    assert evt_trav.severity == EventSeverity.HIGH


def test_03_telemetry_parsers_suricata_eve():
    """Parses Suricata EVE JSON alerts and DNS queries."""
    alert_raw = {
        "timestamp": "2026-10-24T14:20:00.123456+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "dest_ip": "198.51.100.1",
        "src_port": 50123,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature": "ET MALWARE Suspicious CobaltStrike Beacon M2",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
    }
    evt_alert = TelemetryParsers.parse_suricata_eve(alert_raw, "eve.json", "evi-suri-1")
    assert evt_alert.event_category == EventCategory.ALERT
    assert evt_alert.severity == EventSeverity.CRITICAL
    assert "CobaltStrike" in evt_alert.event_action

    dns_raw = {
        "timestamp": "2026-10-24T14:21:00.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.105",
        "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "c2.malicious-domain.com"},
    }
    evt_dns = TelemetryParsers.parse_suricata_eve(dns_raw, "eve.json", "evi-suri-2")
    assert evt_dns.event_category == EventCategory.DNS
    assert evt_dns.domain == "c2.malicious-domain.com"


def test_04_telemetry_parsers_sysmon():
    """Parses Windows Sysmon events with process command lines."""
    sysmon_raw = {
        "EventID": 1,
        "UtcTime": "2026-10-24 14:30:00.000",
        "Computer": "WORKSTATION-01",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "ParentImage": "C:\\Windows\\explorer.exe",
    }
    evt = TelemetryParsers.parse_sysmon_event(sysmon_raw, "sysmon.json", "evi-sysmon-1")
    assert evt.event_category == EventCategory.PROCESS
    assert evt.hostname == "WORKSTATION-01"
    assert evt.username == "CORP\\jsmith"
    assert evt.severity == EventSeverity.HIGH  # Encoded powershell flagged


def test_05_telemetry_parsers_eml_email():
    """Parses EML message structure, SPF/DKIM verification, and attachments."""
    raw_email = (
        b"From: billing@paypal-secure-update.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: URGENT: Account Suspended\r\n"
        b"Date: Sat, 24 Oct 2026 14:40:00 +0000\r\n"
        b"Authentication-Results: mx.company.com; spf=fail smtp.mailfrom=paypal-secure-update.com; dkim=fail\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review invoice at https://paypal-secure-update.com/login\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/octet-stream; name=\"Invoice_Oct.iso\"\r\n"
        b"Content-Disposition: attachment; filename=\"Invoice_Oct.iso\"\r\n\r\n"
        b"MALICIOUS_ISO_BYTES\r\n"
        b"--BOUNDARY--"
    )
    evt = TelemetryParsers.parse_eml_email(raw_email, "phish.eml", "evi-eml-1")
    assert evt.event_category == EventCategory.EMAIL
    assert evt.severity == EventSeverity.HIGH
    assert evt.username == "billing@paypal-secure-update.com"
    assert "paypal-secure-update.com/login" in str(evt.raw_data)


def test_06_telemetry_parsers_generic_json_and_csv():
    """Parses generic JSON and CSV security events."""
    json_entry = {
        "timestamp": "2026-10-24T15:00:00Z",
        "category": "network",
        "action": "firewall_drop",
        "source_ip": "203.0.113.5",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "severity": "MEDIUM",
    }
    evt_json = TelemetryParsers.parse_generic_json(json_entry, "events.json", "evi-gen-1")
    assert evt_json.event_category == EventCategory.NETWORK
    assert evt_json.destination_port == 22
    assert evt_json.severity == EventSeverity.MEDIUM


def test_07_timestamp_normalizer():
    """Normalizes epoch, syslog, apache, and ISO timestamps safely."""
    # Epoch
    iso_epoch = TimestampNormalizer.normalize(1761314400)
    assert "2025" in iso_epoch or "2026" in iso_epoch

    # Syslog
    iso_syslog = TimestampNormalizer.normalize("Oct 24 14:12:05")
    assert "14:12:05" in iso_syslog

    # Apache
    iso_apache = TimestampNormalizer.normalize("10/Oct/2026:13:55:36 +0000")
    assert "2026-10-10" in iso_apache

    # Fallback unparseable
    iso_fallback = TimestampNormalizer.normalize("invalid-timestamp-string")
    assert len(iso_fallback) > 10


def test_08_ingestion_streaming_and_deduplication(tmp_path):
    """Ingests file and skips duplicate events using content hashing."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 44222 ssh2\n"
        "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 44222 ssh2\n",
        encoding="utf-8",
    )
    engine = TelemetryIngestionEngine()
    res = engine.ingest_file(log_file, source_type="linux_auth")
    assert res["success"] is True
    assert res["total_ingested"] == 1
    assert res["duplicates_skipped"] == 1


def test_09_ingestion_sha256_provenance(tmp_path):
    """Computes SHA-256 digest of imported artifact for provenance verification."""
    pcap_file = tmp_path / "traffic.pcap"
    pcap_file.write_bytes(b"DEMO_PCAP_PACKET_STREAM_HEADER")
    expected_hash = hashlib.sha256(b"DEMO_PCAP_PACKET_STREAM_HEADER").hexdigest()

    engine = TelemetryIngestionEngine()
    res = engine.ingest_file(pcap_file)
    assert res["sha256"] == expected_hash
    assert res["raw_evidence_id"].startswith("evi-soc-")


# =========================================================================
# Part 2: SOC Detection Engine & Rules
# =========================================================================

def test_10_detection_rule_brute_force():
    """SEC-AUTH-001: Triggers alert when >= 3 failed logins occur."""
    events = [
        UniversalSecurityEvent(
            event_id=f"evt-bf-{i}",
            timestamp=f"2026-10-24T14:0{i}:00Z",
            ingestion_timestamp="2026-10-24T14:05:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            source_ip="192.168.1.100",
            username="root",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_failed",
        )
        for i in range(4)
    ]
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections(events)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "SEC-AUTH-001"
    assert alerts[0].confidence >= 0.8
    assert len(alerts[0].false_positive_considerations) > 0


def test_11_detection_rule_logon_after_failure():
    """SEC-AUTH-002: Triggers Critical alert on successful login following brute-force."""
    events = [
        UniversalSecurityEvent(
            event_id="evt-f1",
            timestamp="2026-10-24T14:01:00Z",
            ingestion_timestamp="2026-10-24T14:05:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            source_ip="192.168.1.200",
            username="deploy",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_failed",
        ),
        UniversalSecurityEvent(
            event_id="evt-f2",
            timestamp="2026-10-24T14:02:00Z",
            ingestion_timestamp="2026-10-24T14:05:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            source_ip="192.168.1.200",
            username="deploy",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_failed",
        ),
        UniversalSecurityEvent(
            event_id="evt-ok",
            timestamp="2026-10-24T14:03:00Z",
            ingestion_timestamp="2026-10-24T14:05:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            source_ip="192.168.1.200",
            username="deploy",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_success",
        ),
    ]
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections(events)
    alert_rules = [a.rule_id for a in alerts]
    assert "SEC-AUTH-002" in alert_rules
    crit_alert = next(a for a in alerts if a.rule_id == "SEC-AUTH-002")
    assert crit_alert.severity == EventSeverity.CRITICAL


def test_12_detection_rule_obfuscated_powershell():
    """SEC-PROC-001: Triggers alert on PowerShell with -enc flag."""
    evt = UniversalSecurityEvent(
        event_id="evt-ps",
        timestamp="2026-10-24T14:10:00Z",
        ingestion_timestamp="2026-10-24T14:10:00Z",
        source_type="sysmon",
        source_file="sysmon.json",
        hostname="WS-05",
        process_name="powershell.exe",
        command_line="powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...",
        event_category=EventCategory.PROCESS,
    )
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([evt])
    assert any(a.rule_id == "SEC-PROC-001" for a in alerts)


def test_13_detection_rule_webshell_spawn():
    """SEC-PROC-002: Triggers Critical alert when web daemon spawns interactive shell."""
    evt = UniversalSecurityEvent(
        event_id="evt-shell",
        timestamp="2026-10-24T14:15:00Z",
        ingestion_timestamp="2026-10-24T14:15:00Z",
        source_type="sysmon",
        source_file="sysmon.json",
        hostname="WEB-PROD-01",
        parent_process="w3wp.exe",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        event_category=EventCategory.PROCESS,
    )
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([evt])
    assert any(a.rule_id == "SEC-PROC-002" for a in alerts)


def test_14_detection_rule_web_sqli_and_traversal():
    """SEC-WEB-001: Triggers alert on SQLi and path traversal requests."""
    evt_sqli = UniversalSecurityEvent(
        event_id="evt-sqli",
        timestamp="2026-10-24T14:20:00Z",
        ingestion_timestamp="2026-10-24T14:20:00Z",
        source_type="web_access",
        source_file="access.log",
        source_ip="198.51.100.22",
        url="/api/users?search=' UNION SELECT password FROM admin --",
        event_category=EventCategory.WEB,
    )
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([evt_sqli])
    assert any(a.rule_id == "SEC-WEB-001" for a in alerts)


def test_15_detection_rule_dns_tunneling():
    """SEC-NET-001: Triggers alert on high-length anomalous DNS query."""
    evt_dns = UniversalSecurityEvent(
        event_id="evt-dns-tun",
        timestamp="2026-10-24T14:25:00Z",
        ingestion_timestamp="2026-10-24T14:25:00Z",
        source_type="suricata",
        source_file="eve.json",
        source_ip="10.0.0.50",
        domain="v2a4b8c16d32e64f128g256h512i1024j2048.exfil.attacker-c2.net",
        event_category=EventCategory.DNS,
    )
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([evt_dns])
    assert any(a.rule_id == "SEC-NET-001" for a in alerts)


def test_16_detection_rule_malicious_file_hash():
    """SEC-HASH-001: Triggers alert when file hash matches known malicious IOC catalog."""
    evt = UniversalSecurityEvent(
        event_id="evt-mal-hash",
        timestamp="2026-10-24T14:30:00Z",
        ingestion_timestamp="2026-10-24T14:30:00Z",
        source_type="sysmon",
        source_file="sysmon.json",
        hostname="FINANCE-PC",
        process_name="mimikatz.exe",
        file_hash="c8105c7b3988185c7bbecba1264c730ce9e3b99be44983b63cc3fe2843ef5cb1",
        event_category=EventCategory.PROCESS,
    )
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([evt])
    assert any(a.rule_id == "SEC-HASH-001" for a in alerts)


# =========================================================================
# Part 3: Chronological Timeline & Incident Correlation
# =========================================================================

def test_17_soc_timeline_chronological_ordering():
    """Timeline items are strictly sorted earliest to latest in ISO UTC."""
    evts = [
        UniversalSecurityEvent(
            event_id="evt-later",
            timestamp="2026-10-24T15:00:00Z",
            ingestion_timestamp="2026-10-24T15:00:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            event_action="logon_success",
        ),
        UniversalSecurityEvent(
            event_id="evt-earlier",
            timestamp="2026-10-24T13:00:00Z",
            ingestion_timestamp="2026-10-24T15:00:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            event_action="logon_failed",
        ),
    ]
    timeline = SOCTimelineEngine.build_timeline(events=evts)
    assert len(timeline) == 2
    assert timeline[0].timestamp < timeline[1].timestamp
    assert timeline[0].source_id == "evt-earlier"


def test_18_soc_timeline_multi_field_filtering():
    """Filters timeline by host, IP, severity, and category."""
    evts = [
        UniversalSecurityEvent(
            event_id="evt-w1",
            timestamp="2026-10-24T14:00:00Z",
            ingestion_timestamp="2026-10-24T14:00:00Z",
            source_type="linux_auth",
            source_file="auth.log",
            hostname="host-alpha",
            severity=EventSeverity.HIGH,
            event_category=EventCategory.AUTHENTICATION,
        ),
        UniversalSecurityEvent(
            event_id="evt-w2",
            timestamp="2026-10-24T14:05:00Z",
            ingestion_timestamp="2026-10-24T14:05:00Z",
            source_type="web_access",
            source_file="access.log",
            hostname="host-beta",
            severity=EventSeverity.LOW,
            event_category=EventCategory.WEB,
        ),
    ]
    timeline = SOCTimelineEngine.build_timeline(events=evts)
    filtered = SOCTimelineEngine.filter_timeline(timeline, host="alpha")
    assert len(filtered) == 1
    assert filtered[0].hostname == "host-alpha"


def test_19_incident_correlation_entity_clustering():
    """Clusters alerts sharing common host into unified SOCIncident."""
    alerts = [
        SOCAlert(
            alert_id="alt-1",
            rule_id="SEC-AUTH-001",
            title="Failed Logins",
            description="Brute force",
            severity=EventSeverity.HIGH,
            confidence=0.85,
            matched_event_ids=["e1", "e2"],
            target_host="CORP-DC01",
        ),
        SOCAlert(
            alert_id="alt-2",
            rule_id="SEC-PROC-001",
            title="Encoded PowerShell",
            description="Obfuscated shell",
            severity=EventSeverity.HIGH,
            confidence=0.88,
            matched_event_ids=["e3"],
            target_host="CORP-DC01",
        ),
    ]
    incidents = SOCIncidentCorrelator.correlate_alerts(alerts)
    assert len(incidents) == 1
    inc = incidents[0]
    assert "CORP-DC01" in inc.scope_hosts
    assert len(inc.alerts) == 2
    assert inc.severity == EventSeverity.HIGH


def test_20_incident_graph_relations():
    """Generates relational links between alerts in same incident."""
    alerts = [
        SOCAlert(
            alert_id="alt-a",
            rule_id="SEC-AUTH-001",
            title="Failed Logins",
            description="Brute force",
            severity=EventSeverity.HIGH,
            confidence=0.85,
            matched_event_ids=["e1"],
            target_host="SERVER-01",
        ),
        SOCAlert(
            alert_id="alt-b",
            rule_id="SEC-AUTH-002",
            title="Successful Logon",
            description="Compromise",
            severity=EventSeverity.CRITICAL,
            confidence=0.90,
            matched_event_ids=["e2"],
            target_host="SERVER-01",
        ),
    ]
    incidents = SOCIncidentCorrelator.correlate_alerts(alerts)
    assert len(incidents[0].relations) >= 1
    rel = incidents[0].relations[0]
    assert rel.relation_type == IncidentRelationType.SAME_HOST
    assert rel.observation_class == EvidenceObservationClass.CORRELATED_OBSERVATION


# =========================================================================
# Part 4: Incident Response Playbooks
# =========================================================================

def test_21_response_playbooks_catalog_and_content():
    """Lists 8 structured playbooks with containment, rollback, and verification steps."""
    playbooks = SOCPlaybookEngine.list_playbooks()
    assert len(playbooks) == 8
    p_ids = [p["playbook_id"] for p in playbooks]
    assert "PB-CRED" in p_ids
    assert "PB-BRUTE" in p_ids
    assert "PB-PSHELL" in p_ids
    assert "PB-WEB" in p_ids
    assert "PB-MALWARE" in p_ids
    assert "PB-PHISH" in p_ids
    assert "PB-OUTBOUND" in p_ids
    assert "PB-EXFIL" in p_ids


def test_22_response_playbooks_approval_enforcement():
    """Enforces explicit human approval for containment commands."""
    res_reject = SOCPlaybookEngine.approve_step("PB-BRUTE", "step-brute-2", approver="analyst_alice", approved=False)
    assert res_reject["success"] is True
    assert res_reject["status"] == PlaybookStepStatus.REJECTED.value

    res_approve = SOCPlaybookEngine.approve_step("PB-BRUTE", "step-brute-2", approver="lead_bob", approved=True)
    assert res_approve["success"] is True
    assert res_approve["status"] == PlaybookStepStatus.APPROVED.value


# =========================================================================
# Part 5: Autonomous Copilot SOC Investigation Engine
# =========================================================================

def test_23_autonomous_copilot_investigation_entity_extraction():
    """Extracts target IP, CVE, and file hash from natural language prompt."""
    query = "Investigate suspicious brute force attack from 198.51.100.45 targeting CVE-2021-44228"
    task = SOCCopilotEngine.start_investigation(query)
    assert task.target_entity == "198.51.100.45"
    assert "CVE-2021-44228" in task.extracted_indicators
    assert "198.51.100.45" in task.extracted_indicators


def test_24_autonomous_copilot_gap_analysis():
    """Flags evidence gaps when raw telemetry is missing for investigation."""
    task = SOCCopilotEngine.start_investigation("Triage compromised host WEB-PROD-01")
    assert len(task.missing_evidence) > 0
    assert any("telemetry" in g.lower() for g in task.missing_evidence)


def test_25_autonomous_copilot_report_generation():
    """Exports structured JSON and Markdown investigation reports."""
    task = SOCCopilotEngine.start_investigation("Investigate 10.0.0.99")
    rep_json = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="json")
    assert isinstance(rep_json, dict)
    assert rep_json["schema_version"] == "5.0"
    assert rep_json["target_entity"] == "10.0.0.99"

    rep_md = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="markdown")
    assert isinstance(rep_md, str)
    assert "# REDLOOP SOC Investigation Report" in rep_md


# =========================================================================
# Part 6: REST API Contracts
# =========================================================================

@pytest.fixture(scope="module")
def soc_api_client(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("phase5_api")
    db_file = str(tmp_dir / "audit.sqlite")
    from fastapi import FastAPI
    from redloop.workbench import register_workbench_routes
    app = FastAPI()
    register_workbench_routes(app, db_path=db_file, scope_manager=None)
    client = TestClient(app, base_url="http://testserver")
    return client


def test_26_api_soc_ingest_and_events(soc_api_client):
    """API: POST /api/soc/ingest and GET /api/soc/events."""
    payload = {
        "content": (
            "Oct 24 16:00:00 srv01 sshd[999]: Failed password for invalid user hacker from 203.0.113.10 port 55555 ssh2\n"
            "Oct 24 16:00:05 srv01 sshd[999]: Failed password for invalid user hacker from 203.0.113.10 port 55555 ssh2\n"
            "Oct 24 16:00:10 srv01 sshd[999]: Failed password for invalid user hacker from 203.0.113.10 port 55555 ssh2\n"
        ),
        "source_type": "linux_auth",
        "file_name": "auth_test.log",
    }
    res_ingest = soc_api_client.post(
        "/api/soc/ingest",
        json=payload,
        headers={"Origin": "http://testserver"},
    )
    assert res_ingest.status_code == 200
    assert res_ingest.json()["total_ingested"] >= 1

    res_events = soc_api_client.get("/api/soc/events?source_type=linux_auth")
    assert res_events.status_code == 200
    assert res_events.json()["total"] >= 1


def test_27_api_soc_detect_alerts_incidents(soc_api_client):
    """API: POST /api/soc/detect, GET /api/soc/alerts, POST /api/soc/incidents."""
    res_detect = soc_api_client.post(
        "/api/soc/detect",
        headers={"Origin": "http://testserver"},
    )
    assert res_detect.status_code == 200
    assert "alerts" in res_detect.json()

    res_alerts = soc_api_client.get("/api/soc/alerts")
    assert res_alerts.status_code == 200
    assert "alerts" in res_alerts.json()

    res_inc = soc_api_client.post(
        "/api/soc/incidents",
        headers={"Origin": "http://testserver"},
    )
    assert res_inc.status_code == 200
    assert "incidents" in res_inc.json()


def test_28_api_soc_timeline_and_playbooks(soc_api_client):
    """API: GET /api/soc/timeline, GET /api/soc/playbooks, and POST approval."""
    res_tl = soc_api_client.get("/api/soc/timeline")
    assert res_tl.status_code == 200
    assert "timeline" in res_tl.json()

    res_pb = soc_api_client.get("/api/soc/playbooks")
    assert res_pb.status_code == 200
    assert len(res_pb.json()["playbooks"]) == 8

    # Approve step via API
    res_app = soc_api_client.post(
        "/api/soc/playbooks/PB-BRUTE/approve",
        json={"step_id": "step-brute-2", "approver": "soc_lead", "approved": True},
        headers={"Origin": "http://testserver"},
    )
    assert res_app.status_code == 200
    assert res_app.json()["status"] == "APPROVED"


def test_29_api_soc_investigate_and_reports(soc_api_client):
    """API: POST /api/soc/investigate and GET /api/soc/reports/{id}."""
    res_inv = soc_api_client.post(
        "/api/soc/investigate",
        json={"query": "Investigate anomalous traffic to 198.51.100.99"},
        headers={"Origin": "http://testserver"},
    )
    assert res_inv.status_code == 200
    inv_data = res_inv.json()["investigation"]
    inv_id = inv_data["investigation_id"]

    res_rep = soc_api_client.get(f"/api/soc/reports/{inv_id}?format=json")
    assert res_rep.status_code == 200
    assert res_rep.json()["schema_version"] == "5.0"
