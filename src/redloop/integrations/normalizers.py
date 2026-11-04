"""Cross-Platform Security Telemetry Normalizer (Phase 8).

Transforms raw alerts and search records from external SIEM, EDR, and Identity providers
into standardized REDLOOP UniversalSecurityEvent models, preserving source fidelity,
timestamps, and raw evidence links.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    ParserStatus,
    UniversalSecurityEvent,
)


def compute_dedup_id(provider_id: str, record_id: str) -> str:
    """Generates a deterministic event ID bound to provider and source record identity."""
    clean_p = provider_id.lower().strip()
    clean_r = str(record_id).strip()
    return f"{clean_p}:{clean_r}"


def _parse_timestamp(raw_ts: Optional[str]) -> str:
    """Safely normalizes varied date formats into RFC 3339 / ISO 8601 UTC."""
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()
    try:
        # Standard ISO
        dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass
    # Unix epoch fallback
    try:
        val = float(raw_ts)
        if val > 1e11:  # milliseconds
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return datetime.now(timezone.utc).isoformat()


def _map_severity(raw_level: Any) -> EventSeverity:
    """Maps diverse provider severity representations (integer or string) to EventSeverity."""
    if isinstance(raw_level, int):
        # Wazuh rule levels (0-15)
        if raw_level >= 12:
            return EventSeverity.CRITICAL
        elif raw_level >= 8:
            return EventSeverity.HIGH
        elif raw_level >= 4:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW

    s = str(raw_level).upper().strip()
    if s in ("CRITICAL", "VERY_HIGH", "SEV1", "1"):
        return EventSeverity.CRITICAL
    elif s in ("HIGH", "SEV2", "2"):
        return EventSeverity.HIGH
    elif s in ("MEDIUM", "MODERATE", "SEV3", "3"):
        return EventSeverity.MEDIUM
    elif s in ("LOW", "INFORMATIONAL", "INFO", "SEV4", "SEV5", "4", "5"):
        return EventSeverity.LOW
    return EventSeverity.MEDIUM


# =============================================================================
# 1. Wazuh Alert Normalizer
# =============================================================================

def normalize_wazuh_alert(
    raw: dict[str, Any],
    provider_id: str = "wazuh",
) -> UniversalSecurityEvent:
    """Normalizes a native Wazuh manager alert document."""
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})

    rule_id = str(rule.get("id", "0"))
    alert_id = raw.get("id") or raw.get("_id") or f"{rule_id}_{raw.get('timestamp', '')}"
    event_id = compute_dedup_id(provider_id, alert_id)

    # Category determination
    groups = rule.get("groups", [])
    cat = EventCategory.SYSTEM
    if any(g in ("authentication_failed", "authentication_success", "sshd", "pam") for g in groups):
        cat = EventCategory.AUTHENTICATION
    elif any(g in ("sysmon_process_create", "process", "audit") for g in groups):
        cat = EventCategory.PROCESS
    elif any(g in ("web", "apache", "nginx") for g in groups):
        cat = EventCategory.WEB
    elif any(g in ("firewall", "ids", "netfilter") for g in groups):
        cat = EventCategory.NETWORK

    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dst_ip")
    user = data.get("dstuser") or data.get("srcuser") or raw.get("predecoder", {}).get("user")
    host = agent.get("name") or agent.get("ip") or "wazuh-agent"

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(raw.get("timestamp")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file="wazuh_alerts.json",
        hostname=host,
        username=user,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=int(data.get("srcport", 0)) if data.get("srcport") else None,
        destination_port=int(data.get("dstport", 0)) if data.get("dstport") else None,
        protocol=data.get("protocol"),
        event_category=cat,
        event_action=rule.get("description", "Wazuh Alert"),
        process_name=data.get("process_name") or data.get("program_name"),
        process_id=int(data.get("process_id", 0)) if data.get("process_id") else None,
        command_line=data.get("command_line") or data.get("cmdline") or data.get("command"),
        severity=_map_severity(rule.get("level", 5)),
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{agent.get('id', 'master')}",
        raw_data=raw,
        metadata={"wazuh_rule_id": rule_id, "wazuh_groups": groups},
    )


# =============================================================================
# 2. Elastic Security Alert Normalizer
# =============================================================================

def normalize_elastic_alert(
    raw: dict[str, Any],
    provider_id: str = "elastic_security",
) -> UniversalSecurityEvent:
    """Normalizes an Elastic Security / ECS detection alert."""
    src = raw.get("_source", raw)
    doc_id = raw.get("_id") or src.get("id") or str(uuid.uuid4().hex[:12])
    event_id = compute_dedup_id(provider_id, doc_id)

    kibana = src.get("kibana.alert", {}) or src.get("signal", {})
    rule = kibana.get("rule", {}) or src.get("rule", {})

    host = src.get("host", {}).get("name") if isinstance(src.get("host"), dict) else src.get("host")
    user = src.get("user", {}).get("name") if isinstance(src.get("user"), dict) else src.get("user")
    source_ip = src.get("source", {}).get("ip") if isinstance(src.get("source"), dict) else src.get("source_ip")
    dest_ip = src.get("destination", {}).get("ip") if isinstance(src.get("destination"), dict) else src.get("destination_ip")

    # ECS category mapping
    category_list = src.get("event", {}).get("category", [])
    if isinstance(category_list, str):
        category_list = [category_list]

    cat = EventCategory.SYSTEM
    if "authentication" in category_list:
        cat = EventCategory.AUTHENTICATION
    elif "process" in category_list:
        cat = EventCategory.PROCESS
    elif "network" in category_list:
        cat = EventCategory.NETWORK
    elif "web" in category_list:
        cat = EventCategory.WEB

    process_name = src.get("process", {}).get("name") if isinstance(src.get("process"), dict) else None
    process_pid = src.get("process", {}).get("pid") if isinstance(src.get("process"), dict) else None

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(src.get("@timestamp") or src.get("timestamp")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file=".alerts-security.alerts-default",
        hostname=host,
        username=user,
        source_ip=source_ip,
        destination_ip=dest_ip,
        event_category=cat,
        event_action=rule.get("name") or src.get("event", {}).get("action", "Elastic Detection Alert"),
        process_name=process_name,
        process_id=int(process_pid) if process_pid else None,
        severity=_map_severity(rule.get("severity") or src.get("severity", "medium")),
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{rule.get('id', 'default')}",
        raw_data=raw,
        metadata={"elastic_rule_name": rule.get("name"), "elastic_risk_score": rule.get("risk_score")},
    )


# =============================================================================
# 3. Splunk Event / Search Result Normalizer
# =============================================================================

def normalize_splunk_event(
    raw: dict[str, Any],
    provider_id: str = "splunk",
) -> UniversalSecurityEvent:
    """Normalizes a Splunk search job result row."""
    cd_id = raw.get("_cd") or raw.get("_bkt") or str(uuid.uuid4().hex[:10])
    event_id = compute_dedup_id(provider_id, cd_id)

    host = raw.get("host") or raw.get("dest") or raw.get("dvc")
    user = raw.get("user") or raw.get("src_user") or raw.get("dest_user")
    src_ip = raw.get("src") or raw.get("src_ip")
    dst_ip = raw.get("dest") or raw.get("dest_ip")

    cat = EventCategory.SYSTEM
    action = raw.get("action") or raw.get("signature") or raw.get("_raw", "Splunk Event")[:60]
    if any(term in action.lower() for term in ("login", "logon", "auth")):
        cat = EventCategory.AUTHENTICATION
    elif any(term in action.lower() for term in ("process", "exec", "cmd")):
        cat = EventCategory.PROCESS
    elif any(term in action.lower() for term in ("traffic", "connect", "dns")):
        cat = EventCategory.NETWORK

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(raw.get("_time")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file=raw.get("source", "splunk_index"),
        hostname=host,
        username=user,
        source_ip=src_ip,
        destination_ip=dst_ip,
        event_category=cat,
        event_action=action,
        severity=_map_severity(raw.get("severity", "medium")),
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{raw.get('index', 'main')}",
        raw_data=raw,
        metadata={"splunk_sourcetype": raw.get("sourcetype"), "splunk_index": raw.get("index")},
    )


# =============================================================================
# 4. Microsoft Defender for Endpoint Alert Normalizer
# =============================================================================

def normalize_defender_alert(
    raw: dict[str, Any],
    provider_id: str = "defender_endpoint",
) -> UniversalSecurityEvent:
    """Normalizes a Microsoft Defender for Endpoint alert entity."""
    alert_id = raw.get("id") or str(uuid.uuid4().hex[:12])
    event_id = compute_dedup_id(provider_id, alert_id)

    host = raw.get("computerDnsName") or raw.get("machineId")
    cat = EventCategory.ENDPOINT
    if raw.get("category") == "LateralMovement":
        cat = EventCategory.NETWORK
    elif raw.get("category") == "Execution":
        cat = EventCategory.PROCESS
    elif raw.get("category") == "CredentialAccess":
        cat = EventCategory.AUTHENTICATION

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(raw.get("alertCreationTime") or raw.get("firstEventTime")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file="defender_alerts_api",
        hostname=host,
        username=raw.get("accountName"),
        source_ip=raw.get("lastIpAddress"),
        event_category=cat,
        event_action=raw.get("title", "Defender for Endpoint Alert"),
        severity=_map_severity(raw.get("severity", "Medium")),
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{raw.get('detectionSource', 'EDR')}",
        raw_data=raw,
        metadata={"defender_threat_name": raw.get("threatName"), "defender_category": raw.get("category")},
    )


# =============================================================================
# 5. CrowdStrike Falcon Detection Normalizer
# =============================================================================

def normalize_crowdstrike_detection(
    raw: dict[str, Any],
    provider_id: str = "crowdstrike_falcon",
) -> UniversalSecurityEvent:
    """Normalizes a CrowdStrike Falcon detection summary."""
    det_id = raw.get("detection_id") or raw.get("composite_id") or str(uuid.uuid4().hex[:12])
    event_id = compute_dedup_id(provider_id, det_id)

    device = raw.get("device", {})
    behaviors = raw.get("behaviors", [{}])
    primary_behavior = behaviors[0] if behaviors else {}

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(raw.get("created_timestamp") or primary_behavior.get("timestamp")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file="crowdstrike_detections_api",
        hostname=device.get("hostname"),
        username=primary_behavior.get("user_name"),
        source_ip=device.get("local_ip") or device.get("external_ip"),
        event_category=EventCategory.PROCESS,
        event_action=primary_behavior.get("scenario") or primary_behavior.get("tactic", "CrowdStrike Detection"),
        process_name=primary_behavior.get("filename"),
        command_line=primary_behavior.get("cmdline"),
        file_hash=primary_behavior.get("sha256"),
        severity=_map_severity(raw.get("max_severity_displayname") or raw.get("max_severity", 50)),
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{device.get('cid', 'falcon')}",
        raw_data=raw,
        metadata={"falcon_technique": primary_behavior.get("technique")},
    )


# =============================================================================
# 6. Microsoft Entra ID Sign-In Normalizer
# =============================================================================

def normalize_entra_signin(
    raw: dict[str, Any],
    provider_id: str = "entra_id",
) -> UniversalSecurityEvent:
    """Normalizes a Microsoft Entra ID / Azure AD audit sign-in log."""
    sign_id = raw.get("id") or str(uuid.uuid4().hex[:12])
    event_id = compute_dedup_id(provider_id, sign_id)

    status_code = raw.get("status", {}).get("errorCode", 0)
    is_failed = status_code != 0
    sev = EventSeverity.HIGH if (is_failed and raw.get("riskLevelDuringSignIn") in ("high", "medium")) else (EventSeverity.MEDIUM if is_failed else EventSeverity.LOW)

    return UniversalSecurityEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(raw.get("createdDateTime")),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        source_type=provider_id,
        source_file="entra_signin_logs",
        hostname=raw.get("deviceDetail", {}).get("displayName"),
        username=raw.get("userPrincipalName") or raw.get("userDisplayName"),
        source_ip=raw.get("ipAddress"),
        event_category=EventCategory.AUTHENTICATION,
        event_action="failed_signin" if is_failed else "successful_signin",
        severity=sev,
        parser_status=ParserStatus.PARSED,
        provenance=f"PROVIDER:{provider_id}:{raw.get('appDisplayName', 'AzurePortal')}",
        raw_data=raw,
        metadata={"entra_app_id": raw.get("appId"), "risk_detail": raw.get("riskDetail")},
    )
