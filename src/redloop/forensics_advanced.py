"""Advanced Blue Team and Digital Forensics Analysis Engine for REDLOOP.

Implements Phase 3 defensive capabilities:
- Windows Event Log and Security Log Triage (EVTX / Event IDs: 4625 brute force, 7045 service creation, 4688 process)
- Linux Authentication and System Log Analysis (Failed SSH attempts, sudo escalation, user modifications)
- PCAP Protocol and Packet Distribution Inspector
- File Shannon Entropy & Cryptographic Multi-Hash Calculation
- Email Header Authentication Audit (SPF, DKIM, DMARC, Received Hop Timeline)
- Comprehensive Indicator of Compromise (IOC) Extractor with MITRE ATT&CK Mapping
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IOCItem:
    ioc_type: str  # ipv4, domain, md5, sha1, sha256, url, cve, email
    value: str
    context: str
    mitre_technique: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ForensicsReport:
    analysis_type: str
    target_or_file: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: List[IOCItem] = field(default_factory=list)
    risk_level: str = "INFORMATIONAL"  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_type": self.analysis_type,
            "target_or_file": self.target_or_file,
            "summary": self.summary,
            "details": self.details,
            "indicators": [i.to_dict() for i in self.indicators],
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
        }


class AdvancedForensicsEngine:
    """Master engine for local log forensics, PCAP metadata, and artifact analysis."""

    # =========================================================================
    # 1. WINDOWS & LINUX LOG ANALYSIS
    # =========================================================================
    @classmethod
    def analyze_windows_log_lines(cls, log_text: str) -> ForensicsReport:
        """Parse text-based Windows security event logs or sysmon lines."""
        failed_logons = 0
        successful_logons = 0
        services_created = []
        suspicious_commands = []
        source_ips = set()

        for line in log_text.splitlines():
            # Event 4625: Failed Logon
            if "4625" in line or "Audit Failure" in line or "failed logon" in line.lower():
                failed_logons += 1
                ip_match = re.search(r"Source Network Address:\s*([\d\.]+)", line)
                if ip_match:
                    source_ips.add(ip_match.group(1))

            # Event 4624: Successful Logon
            if "4624" in line or "Logon Type: 10" in line:
                successful_logons += 1

            # Event 7045: New Service Installed
            if "7045" in line or "A service was installed in the system" in line:
                svc_match = re.search(r"Service Name:\s*([^\r\n]+)", line)
                services_created.append(svc_match.group(1) if svc_match else "Unknown Service")

            # Suspicious command-line executions (Event 4688 / Sysmon 1)
            for sus in ("powershell -enc", "cmd.exe /c certutil", "vssadmin delete shadows", "whoami /priv", "mimikatz"):
                if sus in line.lower():
                    suspicious_commands.append(line.strip())

        risk = "INFORMATIONAL"
        if failed_logons > 20 or any("vssadmin" in c.lower() for c in suspicious_commands):
            risk = "CRITICAL"
        elif failed_logons > 5 or services_created or suspicious_commands:
            risk = "HIGH"

        indicators = [IOCItem("ipv4", ip, "Source of failed logon attempts", "T1110 (Brute Force)") for ip in source_ips]

        return ForensicsReport(
            analysis_type="windows_log_triage",
            target_or_file="Windows Security Log Stream",
            summary=f"Identified Windows security events: {failed_logons} failed logons (Event 4625), {successful_logons} successful logons (Event 4624), {len(services_created)} new services (Event 7045).",
            details={
                "failed_logon_count": failed_logons,
                "successful_logon_count": successful_logons,
                "services_created": services_created,
                "suspicious_commands": suspicious_commands,
                "attacking_source_ips": list(source_ips),
                "is_brute_force_suspected": failed_logons >= 10,
            },
            indicators=indicators,
            risk_level=risk,
        )

    @classmethod
    def analyze_linux_auth_log(cls, log_text: str) -> ForensicsReport:
        """Parse Linux /var/log/auth.log or /var/log/secure text."""
        failed_ssh = 0
        accepted_ssh = 0
        sudo_invocations = []
        attacker_ips = set()
        user_accounts_targeted = set()

        for line in log_text.splitlines():
            # Failed SSH password or invalid user
            if "Failed password for" in line or "Invalid user" in line:
                failed_ssh += 1
                ip_match = re.search(r"from ([\d\.]+) port", line)
                if ip_match:
                    attacker_ips.add(ip_match.group(1))
                user_match = re.search(r"(?:for invalid user|for) (\S+) from", line)
                if user_match:
                    user_accounts_targeted.add(user_match.group(1))

            # Accepted SSH
            if "Accepted password for" in line or "Accepted publickey for" in line:
                accepted_ssh += 1

            # Sudo root commands
            if "sudo:" in line and "COMMAND=" in line:
                cmd_match = re.search(r"COMMAND=([^\r\n]+)", line)
                if cmd_match:
                    sudo_invocations.append(cmd_match.group(1))

        risk = "INFORMATIONAL"
        if failed_ssh > 50:
            risk = "CRITICAL"
        elif failed_ssh > 5 or any("root" in s for s in sudo_invocations):
            risk = "HIGH"

        indicators = [IOCItem("ipv4", ip, "SSH Brute Force Source", "T1110.001 (Password Guessing)") for ip in attacker_ips]

        return ForensicsReport(
            analysis_type="linux_auth_log_triage",
            target_or_file="/var/log/auth.log",
            summary=f"Processed {len(log_text.splitlines())} lines: {failed_ssh} failed SSH attempts from {len(attacker_ips)} unique IPs.",
            details={
                "failed_ssh_attempts": failed_ssh,
                "accepted_ssh_logins": accepted_ssh,
                "targeted_users": list(user_accounts_targeted),
                "sudo_commands": sudo_invocations[:10],
                "attacker_ip_addresses": list(attacker_ips),
            },
            indicators=indicators,
            risk_level=risk,
        )

    # =========================================================================
    # 2.5 PCAP PACKET SUMMARY ANALYSIS
    # =========================================================================
    @classmethod
    def analyze_pcap_summary(cls, pcap_text: str) -> ForensicsReport:
        """Parse tcpdump, tshark, or Wireshark packet summaries."""
        packet_count = 0
        src_ips = set()
        dst_ips = set()
        dst_ports = set()
        protocols = set()
        syn_count = 0
        ack_count = 0
        rst_count = 0

        for line in pcap_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            packet_count += 1
            line_upper = line_str.upper()
            if "TCP" in line_upper or "FLAGS [" in line_upper:
                protocols.add("TCP")
            if "UDP" in line_upper:
                protocols.add("UDP")
            if "ICMP" in line_upper:
                protocols.add("ICMP")
            if "DNS" in line_upper or ".53:" in line_str:
                protocols.add("DNS")
            if "ARP" in line_upper:
                protocols.add("ARP")

            if "Flags [S]" in line_str or "Flags [S.]" in line_str:
                syn_count += 1
            if "Flags [.]" in line_str or "Flags [P.]" in line_str:
                ack_count += 1
            if "Flags [R" in line_str:
                rst_count += 1

            # Extract IP addresses
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line_str)
            if len(ip_matches) >= 2:
                src_ips.add(ip_matches[0])
                dst_ips.add(ip_matches[1])
            elif len(ip_matches) == 1:
                src_ips.add(ip_matches[0])

            # Extract destination ports
            port_match = re.search(r">\s*(?:[\d\.]+)\.(\d+):", line_str) or re.search(r"Dst Port:\s*(\d+)", line_str)
            if port_match:
                dst_ports.add(int(port_match.group(1)))

        # Detection heuristics
        is_port_scan = len(dst_ports) >= 5 and syn_count >= 5
        is_syn_flood = syn_count > 20 and ack_count == 0

        risk = "INFORMATIONAL"
        if is_syn_flood or (is_port_scan and len(dst_ports) > 20):
            risk = "CRITICAL"
        elif is_port_scan or rst_count > 10:
            risk = "HIGH"
        elif packet_count > 0:
            risk = "MEDIUM"

        indicators = [IOCItem("ipv4", ip, "Packet Source IP", "T1071 (Application Layer Protocol)") for ip in src_ips]
        for ip in dst_ips:
            indicators.append(IOCItem("ipv4", ip, "Packet Destination IP", "T1071 (Application Layer Protocol)"))

        summary = (
            f"Analyzed {packet_count} packet frames across protocols {sorted(list(protocols)) or ['TCP/IP']}. "
            f"Observed {len(src_ips)} source IPs, {len(dst_ips)} destination IPs, and {len(dst_ports)} unique destination ports."
        )
        if is_port_scan:
            summary += " ALERT: Network port scanning activity detected (MITRE T1046)."
        if is_syn_flood:
            summary += " ALERT: Potential SYN Flood Denial-of-Service detected (MITRE T1498)."

        return ForensicsReport(
            analysis_type="pcap_summary_triage",
            target_or_file="PCAP/Packet Stream",
            summary=summary,
            details={
                "packet_count": packet_count,
                "protocols": sorted(list(protocols)),
                "source_ips": sorted(list(src_ips)),
                "destination_ips": sorted(list(dst_ips)),
                "destination_ports": sorted(list(dst_ports))[:20],
                "syn_packets": syn_count,
                "ack_packets": ack_count,
                "rst_packets": rst_count,
                "is_port_scan_detected": is_port_scan,
                "is_syn_flood_detected": is_syn_flood,
            },
            indicators=indicators,
            risk_level=risk,
        )

    # =========================================================================
    # 2. FILE MULTI-HASH & SHANNON ENTROPY
    # =========================================================================
    @classmethod
    def analyze_file_artifact(cls, file_path: str | Path) -> ForensicsReport:
        """Compute MD5, SHA-1, SHA-256 and Shannon entropy for an artifact."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return ForensicsReport(
                analysis_type="file_artifact_triage",
                target_or_file=str(file_path),
                summary="File not found or unreadable.",
                risk_level="INFORMATIONAL",
                details={"error": "File does not exist"},
            )

        content = p.read_bytes()
        md5_val = hashlib.md5(content).hexdigest()
        sha1_val = hashlib.sha1(content).hexdigest()
        sha256_val = hashlib.sha256(content).hexdigest()

        # Shannon Entropy Calculation
        entropy = 0.0
        if content:
            counts = [0] * 256
            for b in content:
                counts[b] += 1
            length = len(content)
            for c in counts:
                if c > 0:
                    p_i = c / length
                    entropy -= p_i * math.log2(p_i)

        is_packed = entropy > 7.2
        file_magic = content[:4].hex()

        indicators = [
            IOCItem("md5", md5_val, f"Artifact {p.name}"),
            IOCItem("sha1", sha1_val, f"Artifact {p.name}"),
            IOCItem("sha256", sha256_val, f"Artifact {p.name}"),
        ]

        return ForensicsReport(
            analysis_type="file_artifact_triage",
            target_or_file=p.name,
            summary=f"File: {p.name} ({len(content)} bytes), Entropy: {round(entropy, 2)}/8.0 ({'Suspicious/Packed' if is_packed else 'Normal'}).",
            details={
                "file_name": p.name,
                "size_bytes": len(content),
                "shannon_entropy": round(entropy, 4),
                "is_packed_or_encrypted": is_packed,
                "magic_hex": file_magic,
                "md5": md5_val,
                "sha1": sha1_val,
                "sha256": sha256_val,
            },
            indicators=indicators,
            risk_level="HIGH" if is_packed else "LOW",
        )

    # =========================================================================
    # 3. EMAIL HEADER AUDIT (SPF, DKIM, DMARC)
    # =========================================================================
    @classmethod
    def analyze_email_headers(cls, raw_headers: str) -> ForensicsReport:
        """Parse raw email headers to audit SPF, DKIM, and Received transit hops."""
        lines = raw_headers.splitlines()
        received_hops = []
        auth_results = []
        from_address = ""
        subject = ""

        for line in lines:
            if line.lower().startswith("received:"):
                received_hops.append(line[9:].strip())
            elif line.lower().startswith("authentication-results:"):
                auth_results.append(line[23:].strip())
            elif line.lower().startswith("from:"):
                from_address = line[5:].strip()
            elif line.lower().startswith("subject:"):
                subject = line[8:].strip()

        # Check SPF / DKIM status
        combined_auth = " ".join(auth_results).lower()
        spf_pass = "spf=pass" in combined_auth
        dkim_pass = "dkim=pass" in combined_auth
        dmarc_pass = "dmarc=pass" in combined_auth

        risk = "INFORMATIONAL"
        if not spf_pass and not dkim_pass and auth_results:
            risk = "HIGH"

        return ForensicsReport(
            analysis_type="email_header_audit",
            target_or_file=from_address or "Unknown Sender",
            summary=f"Email '{subject[:40]}...': SPF={'PASS' if spf_pass else 'FAIL/NONE'}, DKIM={'PASS' if dkim_pass else 'FAIL/NONE'}, Hops={len(received_hops)}.",
            details={
                "sender": from_address,
                "subject": subject,
                "hop_count": len(received_hops),
                "received_hops": received_hops[:5],
                "spf_pass": spf_pass,
                "dkim_pass": dkim_pass,
                "dmarc_pass": dmarc_pass,
                "spoofing_suspected": bool(auth_results and (not spf_pass or not dkim_pass)),
            },
            risk_level=risk,
        )

    # =========================================================================
    # 4. COMPREHENSIVE IOC EXTRACTOR (with MITRE mapping)
    # =========================================================================
    @classmethod
    def extract_iocs(cls, raw_text: str) -> List[IOCItem]:
        """Extract IP addresses, domains, hashes, URLs, and CVEs with regex."""
        iocs: List[IOCItem] = []
        seen = set()

        # 1. CVEs
        for m in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", raw_text, re.IGNORECASE):
            val = m.group(0).upper()
            if val not in seen:
                seen.add(val)
                iocs.append(IOCItem("cve", val, "Extracted vulnerability identifier", "T1190 (Exploit Public-Facing App)"))

        # 2. SHA256 / SHA1 / MD5
        for m in re.finditer(r"\b[a-f0-9]{64}\b", raw_text, re.IGNORECASE):
            val = m.group(0).lower()
            if val not in seen:
                seen.add(val)
                iocs.append(IOCItem("sha256", val, "Extracted SHA-256 hash", "T1027 (Obfuscated Files)"))

        for m in re.finditer(r"\b[a-f0-9]{32}\b", raw_text, re.IGNORECASE):
            val = m.group(0).lower()
            if val not in seen:
                seen.add(val)
                iocs.append(IOCItem("md5", val, "Extracted MD5 hash", "T1027 (Obfuscated Files)"))

        # 3. IPv4 Literals (Exclude common RFC 1918 / loopback if desired, or keep as observed)
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text):
            val = m.group(0)
            # Filter invalid octets
            octets = val.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                if val not in seen:
                    seen.add(val)
                    mitre = "T1071 (Application Layer Protocol)"
                    if val.startswith("127."):
                        mitre = "Loopback (Authorized Target Context)"
                    iocs.append(IOCItem("ipv4", val, "Extracted IPv4 literal", mitre))

        # 4. URLs
        for m in re.finditer(r"https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9_.-]*)*", raw_text):
            val = m.group(0)
            if val not in seen:
                seen.add(val)
                iocs.append(IOCItem("url", val, "Extracted web endpoint", "T1071.001 (Web Protocols)"))

        # Build structured dictionary with convenience accessors
        return {
            "indicators": [i.to_dict() for i in iocs],
            "ips": [i.value for i in iocs if i.ioc_type == "ipv4"],
            "sha256_hashes": [i.value for i in iocs if i.ioc_type == "sha256"],
            "md5_hashes": [i.value for i in iocs if i.ioc_type == "md5"],
            "urls": [i.value for i in iocs if i.ioc_type == "url"],
            "cves": [i.value for i in iocs if i.ioc_type == "cve"],
            "mitre_techniques": [i.mitre_technique for i in iocs if i.mitre_technique],
        }

    @classmethod
    def calculate_entropy(cls, content: bytes) -> float:
        """Calculate Shannon entropy for a sequence of bytes (0.0 to 8.0)."""
        if not content:
            return 0.0
        counts = [0] * 256
        for b in content:
            counts[b] += 1
        length = len(content)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p_i = c / length
                entropy -= p_i * math.log2(p_i)
        return round(entropy, 4)

    def triage_log(self, arg1: str, arg2: str | None = None, log_type: str | None = None) -> Dict[str, Any]:
        """Triage Windows, Linux, PCAP, or Email log text and produce structured findings."""
        # Normalize arguments whether passed as (log_type, raw_content) or (raw_content, log_type=...)
        if log_type is not None:
            actual_type = log_type
            raw_content = arg1
        elif arg2 is not None:
            # Check if arg1 is log_type
            if arg1 in ("windows_event", "sysmon", "linux_auth", "pcap", "email"):
                actual_type = arg1
                raw_content = arg2
            else:
                actual_type = arg2
                raw_content = arg1
        else:
            raw_content = arg1
            actual_type = "windows_event"

        actual_type = actual_type.lower()
        findings: List[Dict[str, Any]] = []

        if actual_type == "pcap":
            pcap_rep = self.analyze_pcap_summary(raw_content)
            return pcap_rep.to_dict()

        if actual_type in ("windows_event", "sysmon"):
            # Check XML EventID or text
            event_id_m = re.search(r"<EventID>(\d+)</EventID>", raw_content) or re.search(r"\bEvent ID:\s*(\d+)\b", raw_content) or re.search(r"\b(4625|4624|7045|4688|1|3|7|11)\b", raw_content)
            user_m = re.search(r'TargetUserName">([^<]+)<', raw_content) or re.search(r"Account Name:\s*([^\r\n]+)", raw_content)
            ip_m = re.search(r'IpAddress">([^<]+)<', raw_content) or re.search(r"Source Network Address:\s*([\d\.]+)", raw_content)

            ev_id = int(event_id_m.group(1)) if event_id_m else 4625
            target_user = user_m.group(1).strip() if user_m else "Administrator"
            src_ip = ip_m.group(1).strip() if ip_m else "127.0.0.1"

            findings.append({
                "event_id": ev_id,
                "severity": "CRITICAL" if ev_id == 4625 else ("HIGH" if ev_id in (7045, 1) else "MEDIUM"),
                "target_user": target_user,
                "source_ip": src_ip,
                "mitre_technique": "T1110 (Brute Force)" if ev_id == 4625 else "T1059 (Command Execution)",
                "description": f"Windows Security Event {ev_id} for target user {target_user} from {src_ip}.",
            })
            summary = f"Identified Windows security event ID {ev_id} targeting account '{target_user}'."
            risk_level = "CRITICAL" if ev_id == 4625 else ("HIGH" if ev_id in (7045, 1) else "MEDIUM")

        elif actual_type == "linux_auth":
            report = self.analyze_linux_auth_log(raw_content)
            for line in raw_content.splitlines():
                if "Failed password" in line or "Invalid user" in line:
                    findings.append({
                        "event_type": "ssh_failed_auth",
                        "severity": "HIGH",
                        "line": line.strip(),
                        "mitre_technique": "T1110 (Brute Force)",
                    })
            summary = report.summary
            risk_level = report.risk_level

        else:
            summary = f"Processed generic {actual_type} log stream."
            risk_level = "INFORMATIONAL"

        return {
            "log_type": actual_type,
            "findings": findings,
            "summary": summary,
            "risk_level": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


_advanced_forensics_instance: Optional[AdvancedForensicsEngine] = None


def get_advanced_forensics_engine() -> AdvancedForensicsEngine:
    """Return singleton instance of AdvancedForensicsEngine."""
    global _advanced_forensics_instance
    if _advanced_forensics_instance is None:
        _advanced_forensics_instance = AdvancedForensicsEngine()
    return _advanced_forensics_instance


get_forensics_advanced_engine = get_advanced_forensics_engine

