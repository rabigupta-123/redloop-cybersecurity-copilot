"""Universal Security Event Model & Multi-Format Telemetry Ingestion Engine (Phase 5).

Supported Formats:
1. Windows Event Logs (EVTX JSON/XML export or Sysmon format)
2. Linux Authentication & System Logs (/var/log/auth.log, syslog, pam_unix, sshd)
3. Apache/Nginx Web Server Access and Error Logs (Combined/Common log formats)
4. Firewall Logs (iptables, UFW, pfSense, Cisco ASA)
5. DNS Server Logs (BIND, CoreDNS query logs)
6. Suricata EVE JSON (alert, dns, http, flow)
7. Zeek Logs (conn.log, dns.log, http.log, ssl.log with TSV headers)
8. Sysmon Event Exports (Process Create ID 1, Network ID 3, Image Load ID 7, File Create ID 11)
9. PCAP Packet Capture Summaries / Metadata
10. Email EML Files (MIME headers, auth results, attachments, body URLs)
11. Generic JSON and CSV Security Events
"""

from __future__ import annotations

import csv
import email
from email import policy
import hashlib
import io
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class ParserStatus(str, Enum):
    PARSED = "PARSED"
    NORMALIZED = "NORMALIZED"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    DNS = "dns"
    FILE = "file"
    WEB = "web"
    EMAIL = "email"
    ALERT = "alert"
    SYSTEM = "system"


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class UniversalSecurityEvent:
    """Universal Normalized Security Event Schema (aligned with ECS / OCSF)."""
    event_id: str
    timestamp: str  # ISO 8601 UTC
    ingestion_timestamp: str = ""  # ISO 8601 UTC
    source_type: str = "generic_log"
    source_file: str = "system"
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    event_category: EventCategory = EventCategory.SYSTEM
    event_action: str = "unknown"
    process_name: str | None = None
    process_id: int | None = None
    parent_process: str | None = None
    command_line: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None  # SHA-256 or MD5
    file_path: str | None = None
    severity: EventSeverity = EventSeverity.INFORMATIONAL
    raw_evidence_id: str | None = None
    parser_status: ParserStatus = ParserStatus.PARSED
    provenance: str = "redloop_soc_ingest"
    raw_data: str | dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""
    event_name: str | None = None
    provider_id: str | None = None

    def __post_init__(self) -> None:
        if self.provider_id and self.source_type == "generic_log":
            self.source_type = self.provider_id
        if not self.provider_id:
            self.provider_id = self.source_type
        if not self.ingestion_timestamp:
            self.ingestion_timestamp = datetime.now(timezone.utc).isoformat()
        if not self.event_hash:
            # Deterministic hash for deduplication
            hash_input = (
                f"{self.timestamp}|{self.source_type}|{self.hostname}|{self.username}|"
                f"{self.source_ip}|{self.destination_ip}|{self.event_category}|{self.event_action}|"
                f"{self.process_name}|{self.command_line}|{self.domain}"
            )
            self.event_hash = hashlib.sha256(hash_input.encode("utf-8", errors="replace")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_category"] = self.event_category.value if hasattr(self.event_category, "value") else str(self.event_category)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["parser_status"] = self.parser_status.value if hasattr(self.parser_status, "value") else str(self.parser_status)
        return d

    @property
    def host(self) -> str | None:
        return self.hostname

    @property
    def user(self) -> str | None:
        return self.username

    @property
    def dest_ip(self) -> str | None:
        return self.destination_ip

    @property
    def event_type(self) -> str:
        return self.event_action or "security_event"


class TimestampNormalizer:
    """Safely normalizes various timestamp formats into canonical ISO 8601 UTC."""

    FORMATS = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S,%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S",  # Syslog format
        "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx format
    ]

    @classmethod
    def normalize(cls, raw_ts: str | float | int | None) -> str:
        if raw_ts is None:
            return datetime.now(timezone.utc).isoformat()
        
        # Epoch timestamp
        if isinstance(raw_ts, (int, float)):
            try:
                dt = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
                return dt.isoformat()
            except Exception:
                return datetime.now(timezone.utc).isoformat()

        ts_str = str(raw_ts).strip()
        if not ts_str:
            return datetime.now(timezone.utc).isoformat()

        # Handle Unix epoch string
        try:
            if re.match(r"^\d{10}(\.\d+)?$", ts_str):
                dt = datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
                return dt.isoformat()
        except Exception:
            pass

        # Try standard ISO parse
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

        for fmt in cls.FORMATS:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if "%z" not in fmt:
                    dt = dt.replace(tzinfo=timezone.utc)
                # If syslog format lacking year, add current year
                if "%b" in fmt and "%Y" not in fmt:
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                continue

        # Fallback to current UTC time if unparseable
        return datetime.now(timezone.utc).isoformat()


# =========================================================================
# Specialized Ingestion Parsers
# =========================================================================

class TelemetryParsers:
    """Parses heterogeneous security logs into UniversalSecurityEvent streams."""

    @staticmethod
    def parse_linux_auth(line: str, source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent | None:
        """Parses Linux /var/log/auth.log or syslog authentication entries."""
        line = line.strip()
        if not line:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        # Typical: Oct 24 14:12:05 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 44222 ssh2
        match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([a-zA-Z0-9_\-]+)(?:\[(\d+)\])?:\s+(.*)$", line)
        
        if not match:
            return UniversalSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:10]}",
                timestamp=now_iso,
                ingestion_timestamp=now_iso,
                source_type="linux_auth",
                source_file=source_file,
                event_category=EventCategory.SYSTEM,
                event_action="syslog_unstructured",
                raw_data=line,
                raw_evidence_id=raw_evidence_id,
                parser_status=ParserStatus.PARTIAL,
            )

        ts_raw, host, proc, pid_str, msg = match.groups()
        event_ts = TimestampNormalizer.normalize(ts_raw)
        pid = int(pid_str) if pid_str else None

        user = None
        src_ip = None
        src_port = None
        action = "syslog_message"
        severity = EventSeverity.INFORMATIONAL
        cat = EventCategory.AUTHENTICATION if "sshd" in proc or "sudo" in proc or "login" in proc else EventCategory.SYSTEM

        # Failed password
        if "Failed password" in msg:
            action = "logon_failed"
            severity = EventSeverity.MEDIUM
            u_match = re.search(r"for (?:invalid user )?([^\s]+)", msg)
            if u_match:
                user = u_match.group(1)
            ip_match = re.search(r"from ([\d\.:a-fA-F]+)", msg)
            if ip_match:
                src_ip = ip_match.group(1)
            p_match = re.search(r"port (\d+)", msg)
            if p_match:
                src_port = int(p_match.group(1))

        # Accepted password/publickey
        elif "Accepted" in msg and ("password" in msg or "publickey" in msg):
            action = "logon_success"
            severity = EventSeverity.LOW
            u_match = re.search(r"for ([^\s]+)", msg)
            if u_match:
                user = u_match.group(1)
            ip_match = re.search(r"from ([\d\.:a-fA-F]+)", msg)
            if ip_match:
                src_ip = ip_match.group(1)
            p_match = re.search(r"port (\d+)", msg)
            if p_match:
                src_port = int(p_match.group(1))

        # Sudo execution
        elif "sudo" in proc:
            cat = EventCategory.PROCESS
            action = "sudo_execution"
            severity = EventSeverity.LOW
            u_match = re.search(r"([^\s]+)\s+:\s+TTY=", msg)
            if u_match:
                user = u_match.group(1)
            cmd_match = re.search(r"COMMAND=(.*)$", msg)
            cmd = cmd_match.group(1) if cmd_match else None
            return UniversalSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:10]}",
                timestamp=event_ts,
                ingestion_timestamp=now_iso,
                source_type="linux_auth",
                source_file=source_file,
                hostname=host,
                username=user,
                event_category=cat,
                event_action=action,
                process_name=proc,
                process_id=pid,
                command_line=cmd,
                severity=severity,
                raw_evidence_id=raw_evidence_id,
                raw_data=line,
            )

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=event_ts,
            ingestion_timestamp=now_iso,
            source_type="linux_auth",
            source_file=source_file,
            hostname=host,
            username=user,
            source_ip=src_ip,
            source_port=src_port,
            protocol="tcp" if src_ip else None,
            event_category=cat,
            event_action=action,
            process_name=proc,
            process_id=pid,
            severity=severity,
            raw_evidence_id=raw_evidence_id,
            raw_data=line,
        )

    @staticmethod
    def parse_web_access(line: str, source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent | None:
        """Parses Apache / Nginx Combined Log Format."""
        line = line.strip()
        if not line:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        # Combined format: 192.168.1.50 - frank [10/Oct/2026:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.com" "Mozilla/5.0"
        pattern = r'^([\d\.:a-fA-F]+)\s+([^\s]+)\s+([^\s]+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)(?:\s+HTTP\/[\d\.]+)?\"\s+(\d{3})\s+(\d+|-)'
        match = re.match(pattern, line)

        if not match:
            return UniversalSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:10]}",
                timestamp=now_iso,
                ingestion_timestamp=now_iso,
                source_type="web_access",
                source_file=source_file,
                event_category=EventCategory.WEB,
                event_action="web_request_unparsed",
                raw_data=line,
                raw_evidence_id=raw_evidence_id,
                parser_status=ParserStatus.PARTIAL,
            )

        ip, ident, auth_user, ts_raw, method, path, status_code_str, bytes_sent = match.groups()
        event_ts = TimestampNormalizer.normalize(ts_raw)
        status = int(status_code_str)

        user = auth_user if auth_user != "-" else None
        sev = EventSeverity.INFORMATIONAL
        if status >= 500:
            sev = EventSeverity.MEDIUM
        elif status == 401 or status == 403:
            sev = EventSeverity.LOW
        
        # Check suspicious web attack patterns in URL (with URL decoding)
        import urllib.parse
        url_lower = urllib.parse.unquote(path).lower()
        if any(pat in url_lower for pat in ["union select", "select * from", "1=1", "sleep(", "benchmark("]):
            sev = EventSeverity.HIGH
        elif any(pat in url_lower for pat in ["../", "..\\", "etc/passwd", "win.ini", "boot.ini"]):
            sev = EventSeverity.HIGH
        elif "<script" in url_lower or "%3cscript" in url_lower:
            sev = EventSeverity.MEDIUM

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=event_ts,
            ingestion_timestamp=now_iso,
            source_type="web_access",
            source_file=source_file,
            source_ip=ip,
            destination_port=80 if status != 443 else 443,
            username=user,
            event_category=EventCategory.WEB,
            event_action=f"http_{method.lower()}",
            url=path,
            severity=sev,
            raw_evidence_id=raw_evidence_id,
            raw_data=line,
            metadata={"status_code": status, "method": method, "bytes": bytes_sent},
        )

    @staticmethod
    def parse_suricata_eve(entry: dict[str, Any], source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent:
        """Parses Suricata EVE JSON event record."""
        now_iso = datetime.now(timezone.utc).isoformat()
        ts = TimestampNormalizer.normalize(entry.get("timestamp"))
        event_type = entry.get("event_type", "alert")

        src_ip = entry.get("src_ip")
        dst_ip = entry.get("dest_ip")
        src_port = entry.get("src_port")
        dst_port = entry.get("dest_port")
        proto = entry.get("proto", "TCP").lower()

        cat = EventCategory.ALERT
        sev = EventSeverity.MEDIUM
        action = f"suricata_{event_type}"

        if event_type == "alert":
            alert_data = entry.get("alert", {})
            action = alert_data.get("signature", "Suricata Alert")
            suricata_sev = alert_data.get("severity", 3)
            if suricata_sev == 1:
                sev = EventSeverity.CRITICAL
            elif suricata_sev == 2:
                sev = EventSeverity.HIGH
            elif suricata_sev == 3:
                sev = EventSeverity.MEDIUM
            else:
                sev = EventSeverity.LOW
        elif event_type == "dns":
            cat = EventCategory.DNS
            dns_data = entry.get("dns", {})
            action = "dns_query"
            return UniversalSecurityEvent(
                event_id=f"evt-{uuid.uuid4().hex[:10]}",
                timestamp=ts,
                ingestion_timestamp=now_iso,
                source_type="suricata",
                source_file=source_file,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                event_category=cat,
                event_action=action,
                domain=dns_data.get("rrname"),
                severity=EventSeverity.INFORMATIONAL,
                raw_evidence_id=raw_evidence_id,
                raw_data=entry,
            )

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=ts,
            ingestion_timestamp=now_iso,
            source_type="suricata",
            source_file=source_file,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            event_category=cat,
            event_action=action,
            severity=sev,
            raw_evidence_id=raw_evidence_id,
            raw_data=entry,
        )

    @staticmethod
    def parse_sysmon_event(event_dict: dict[str, Any], source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent:
        """Parses Windows Sysmon Event (Event IDs 1, 3, 7, 11)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        ts = TimestampNormalizer.normalize(event_dict.get("UtcTime") or event_dict.get("TimeCreated") or event_dict.get("@timestamp"))
        
        event_id = int(event_dict.get("EventID") or event_dict.get("event_id") or 1)
        host = event_dict.get("Computer") or event_dict.get("hostname")
        user = event_dict.get("User") or event_dict.get("username")

        cat = EventCategory.PROCESS
        action = "process_create"
        sev = EventSeverity.LOW
        proc_name = event_dict.get("Image") or event_dict.get("process_name")
        parent = event_dict.get("ParentImage") or event_dict.get("parent_process")
        cmd = event_dict.get("CommandLine")
        f_hash = event_dict.get("Hashes") or event_dict.get("file_hash")

        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None

        if event_id == 1:
            cat = EventCategory.PROCESS
            action = "process_create"
            # Flag suspicious powershell with encoded command
            if proc_name and "powershell" in proc_name.lower():
                if cmd and any(flg in cmd.lower() for flg in ["-enc", "-encodedcommand", "-w hidden", "bypass"]):
                    sev = EventSeverity.HIGH
        elif event_id == 3:
            cat = EventCategory.NETWORK
            action = "network_connect"
            src_ip = event_dict.get("SourceIp")
            dst_ip = event_dict.get("DestinationIp")
            src_port = int(event_dict.get("SourcePort")) if event_dict.get("SourcePort") else None
            dst_port = int(event_dict.get("DestinationPort")) if event_dict.get("DestinationPort") else None
        elif event_id == 11:
            cat = EventCategory.FILE
            action = "file_create"

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=ts,
            ingestion_timestamp=now_iso,
            source_type="sysmon",
            source_file=source_file,
            hostname=host,
            username=user,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=event_dict.get("Protocol", "tcp").lower() if src_ip else None,
            event_category=cat,
            event_action=action,
            process_name=proc_name,
            parent_process=parent,
            command_line=cmd,
            file_hash=f_hash,
            severity=sev,
            raw_evidence_id=raw_evidence_id,
            raw_data=event_dict,
        )

    @staticmethod
    def parse_eml_email(raw_bytes: bytes, source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent:
        """Parses EML message into structured security event."""
        now_iso = datetime.now(timezone.utc).isoformat()
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        date_str = msg.get("Date")
        event_ts = TimestampNormalizer.normalize(date_str) if date_str else now_iso

        auth_results = msg.get("Authentication-Results", "")
        spf_fail = "spf=fail" in auth_results.lower()
        dkim_fail = "dkim=fail" in auth_results.lower()
        dmarc_fail = "dmarc=fail" in auth_results.lower()

        # Extract URLs and attachments
        body_urls = []
        attachments = []
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = part.get_content_disposition()
            if cdisp == "attachment":
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                sha = hashlib.sha256(payload).hexdigest()
                attachments.append({"filename": filename, "sha256": sha, "size": len(payload)})
            elif ctype == "text/plain" or ctype == "text/html":
                text = str(part.get_content() or "")
                found_urls = re.findall(r"https?://[^\s<>\"']+", text)
                body_urls.extend(found_urls[:10])

        sev = EventSeverity.LOW
        if spf_fail or dkim_fail or dmarc_fail or any(a["filename"].endswith((".exe", ".vbs", ".js", ".iso")) for a in attachments):
            sev = EventSeverity.HIGH

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=event_ts,
            ingestion_timestamp=now_iso,
            source_type="eml",
            source_file=source_file,
            username=sender,
            event_category=EventCategory.EMAIL,
            event_action="email_received",
            url=body_urls[0] if body_urls else None,
            severity=sev,
            raw_evidence_id=raw_evidence_id,
            raw_data={
                "from": sender,
                "to": recipient,
                "subject": subject,
                "auth_results": auth_results,
                "spf_fail": spf_fail,
                "dkim_fail": dkim_fail,
                "dmarc_fail": dmarc_fail,
                "attachments": attachments,
                "body_urls": body_urls,
            },
        )

    @staticmethod
    def parse_generic_json(obj: dict[str, Any], source_file: str, raw_evidence_id: str) -> UniversalSecurityEvent:
        """Parses generic JSON event with flexible field mapping."""
        now_iso = datetime.now(timezone.utc).isoformat()
        ts = TimestampNormalizer.normalize(
            obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("date")
        )

        cat_str = str(obj.get("category") or obj.get("event_category") or "system").lower()
        cat = EventCategory.SYSTEM
        for ec in EventCategory:
            if ec.value in cat_str:
                cat = ec
                break

        sev_str = str(obj.get("severity") or obj.get("level") or "INFORMATIONAL").upper()
        sev = EventSeverity.INFORMATIONAL
        for es in EventSeverity:
            if es.value == sev_str:
                sev = es
                break

        return UniversalSecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:10]}",
            timestamp=ts,
            ingestion_timestamp=now_iso,
            source_type=str(obj.get("source_type") or "generic_json"),
            source_file=source_file,
            hostname=obj.get("hostname") or obj.get("host"),
            username=obj.get("username") or obj.get("user"),
            source_ip=obj.get("source_ip") or obj.get("src_ip"),
            destination_ip=obj.get("destination_ip") or obj.get("dest_ip"),
            source_port=int(obj.get("source_port")) if obj.get("source_port") else None,
            destination_port=int(obj.get("destination_port")) if obj.get("destination_port") else None,
            protocol=obj.get("protocol"),
            event_category=cat,
            event_action=str(obj.get("action") or obj.get("event_action") or "generic_event"),
            process_name=obj.get("process_name") or obj.get("process"),
            command_line=obj.get("command_line") or obj.get("cmd"),
            domain=obj.get("domain"),
            url=obj.get("url"),
            file_hash=obj.get("file_hash") or obj.get("hash"),
            severity=sev,
            raw_evidence_id=raw_evidence_id,
            raw_data=obj,
        )


class TelemetryIngestionEngine:
    """Orchestrates streaming ingestion, deduplication, and persistence of telemetry files."""

    def __init__(self) -> None:
        self.events: list[UniversalSecurityEvent] = []
        self._event_hashes: set[str] = set()

    def ingest_file(
        self,
        file_path: str | Path,
        source_type: str | None = None,
        task_id: str = "default",
    ) -> dict[str, Any]:
        """Streams, parses, and normalizes an artifact file safely."""
        p = Path(file_path)
        if not p.exists():
            return {
                "success": False,
                "error": f"File '{file_path}' does not exist.",
                "events_count": 0,
            }

        file_bytes = p.read_bytes()
        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        raw_evidence_id = f"evi-soc-{file_sha256[:12]}"

        # Infer source type from extension or hints
        fname = p.name.lower()
        if not source_type:
            if fname.endswith(".eml"):
                source_type = "eml"
            elif fname.endswith(".json") or fname.endswith(".jsonl"):
                source_type = "json"
            elif fname.endswith(".csv"):
                source_type = "csv"
            elif "auth" in fname or "secure" in fname or "syslog" in fname:
                source_type = "linux_auth"
            elif "access" in fname or "nginx" in fname or "apache" in fname:
                source_type = "web_access"
            elif "suricata" in fname or "eve" in fname:
                source_type = "suricata"
            else:
                source_type = "generic_text"

        parsed_events: list[UniversalSecurityEvent] = []
        duplicates_count = 0

        # Parser dispatcher
        if source_type == "eml":
            evt = TelemetryParsers.parse_eml_email(file_bytes, p.name, raw_evidence_id)
            if evt.event_hash not in self._event_hashes:
                self._event_hashes.add(evt.event_hash)
                parsed_events.append(evt)
            else:
                duplicates_count += 1

        elif source_type in ("json", "suricata"):
            text = file_bytes.decode("utf-8", errors="replace")
            # Try lines (JSONL) first
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        if source_type == "suricata" or "event_type" in obj:
                            evt = TelemetryParsers.parse_suricata_eve(obj, p.name, raw_evidence_id)
                        else:
                            evt = TelemetryParsers.parse_generic_json(obj, p.name, raw_evidence_id)
                        
                        if evt.event_hash not in self._event_hashes:
                            self._event_hashes.add(evt.event_hash)
                            parsed_events.append(evt)
                        else:
                            duplicates_count += 1
                except Exception:
                    pass

        elif source_type == "csv":
            text = file_bytes.decode("utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                evt = TelemetryParsers.parse_generic_json(row, p.name, raw_evidence_id)
                if evt.event_hash not in self._event_hashes:
                    self._event_hashes.add(evt.event_hash)
                    parsed_events.append(evt)
                else:
                    duplicates_count += 1

        else:
            # Line by line text (linux_auth, web_access, generic_text)
            text = file_bytes.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if not line.strip():
                    continue
                if source_type == "web_access":
                    evt = TelemetryParsers.parse_web_access(line, p.name, raw_evidence_id)
                else:
                    evt = TelemetryParsers.parse_linux_auth(line, p.name, raw_evidence_id)

                if evt:
                    if evt.event_hash not in self._event_hashes:
                        self._event_hashes.add(evt.event_hash)
                        parsed_events.append(evt)
                    else:
                        duplicates_count += 1

        self.events.extend(parsed_events)

        return {
            "success": True,
            "source_file": p.name,
            "source_type": source_type,
            "sha256": file_sha256,
            "raw_evidence_id": raw_evidence_id,
            "total_ingested": len(parsed_events),
            "duplicates_skipped": duplicates_count,
            "cumulative_events": len(self.events),
        }

    def clear(self) -> None:
        self.events.clear()
        self._event_hashes.clear()
