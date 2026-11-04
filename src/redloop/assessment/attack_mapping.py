"""REDLOOP MITRE ATT&CK Mapping & Coverage Engine (Phase 6).

Provides:
1. Versioned MITRE Enterprise ATT&CK v15 authoritative catalog covering all 14 tactics.
2. Comprehensive technique & sub-technique definitions with data sources.
3. Deterministic mapping engine translating Security Events, SOC Alerts, Findings, and Commands into ATT&CK techniques with explainable confidence.
4. Matrix Heatmap Generation & Coverage Metrics across all 14 Enterprise tactics.
5. Export capabilities in JSON and Markdown table formats.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


@dataclass(frozen=True)
class AttackTactic:
    """MITRE ATT&CK Enterprise Tactic."""
    tactic_id: str
    name: str
    description: str
    reference_url: str


@dataclass(frozen=True)
class AttackTechnique:
    """MITRE ATT&CK Enterprise Technique or Sub-technique."""
    technique_id: str
    name: str
    tactic_ids: list[str]
    description: str
    is_subtechnique: bool = False
    parent_id: Optional[str] = None
    data_sources: list[str] = field(default_factory=list)
    reference_url: str = ""


@dataclass
class TechniqueMapping:
    """Result of mapping an event, alert, or finding to an ATT&CK technique."""
    mapping_id: str
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float  # [0.0, 1.0]
    match_rule_id: str
    match_reason: str
    source_entity: str
    evidence_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackMatrixCoverage:
    """Tactic-level matrix coverage summary."""
    total_tactics: int
    covered_tactics: int
    coverage_percentage: float
    total_techniques_mapped: int
    tactics_breakdown: dict[str, dict[str, Any]]
    high_risk_techniques: list[dict[str, Any]]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackCatalog:
    """Authoritative MITRE Enterprise ATT&CK v15 Dataset."""

    # 14 Enterprise Tactics (Ordered per MITRE kill-chain progression)
    TACTICS: dict[str, AttackTactic] = {
        "TA0043": AttackTactic(
            tactic_id="TA0043",
            name="Reconnaissance",
            description="The adversary is trying to gather information they can use to plan future operations.",
            reference_url="https://attack.mitre.org/tactics/TA0043/",
        ),
        "TA0042": AttackTactic(
            tactic_id="TA0042",
            name="Resource Development",
            description="The adversary is trying to establish resources they can use to support operations.",
            reference_url="https://attack.mitre.org/tactics/TA0042/",
        ),
        "TA0001": AttackTactic(
            tactic_id="TA0001",
            name="Initial Access",
            description="The adversary is trying to get into your network.",
            reference_url="https://attack.mitre.org/tactics/TA0001/",
        ),
        "TA0002": AttackTactic(
            tactic_id="TA0002",
            name="Execution",
            description="The adversary is trying to run malicious code.",
            reference_url="https://attack.mitre.org/tactics/TA0002/",
        ),
        "TA0003": AttackTactic(
            tactic_id="TA0003",
            name="Persistence",
            description="The adversary is trying to maintain their foothold.",
            reference_url="https://attack.mitre.org/tactics/TA0003/",
        ),
        "TA0004": AttackTactic(
            tactic_id="TA0004",
            name="Privilege Escalation",
            description="The adversary is trying to gain higher-level permissions.",
            reference_url="https://attack.mitre.org/tactics/TA0004/",
        ),
        "TA0005": AttackTactic(
            tactic_id="TA0005",
            name="Defense Evasion",
            description="The adversary is trying to avoid being detected.",
            reference_url="https://attack.mitre.org/tactics/TA0005/",
        ),
        "TA0006": AttackTactic(
            tactic_id="TA0006",
            name="Credential Access",
            description="The adversary is trying to steal account names and passwords.",
            reference_url="https://attack.mitre.org/tactics/TA0006/",
        ),
        "TA0007": AttackTactic(
            tactic_id="TA0007",
            name="Discovery",
            description="The adversary is trying to figure out your environment.",
            reference_url="https://attack.mitre.org/tactics/TA0007/",
        ),
        "TA0008": AttackTactic(
            tactic_id="TA0008",
            name="Lateral Movement",
            description="The adversary is trying to move through your environment.",
            reference_url="https://attack.mitre.org/tactics/TA0008/",
        ),
        "TA0009": AttackTactic(
            tactic_id="TA0009",
            name="Collection",
            description="The adversary is trying to gather data of interest to their goal.",
            reference_url="https://attack.mitre.org/tactics/TA0009/",
        ),
        "TA0011": AttackTactic(
            tactic_id="TA0011",
            name="Command and Control",
            description="The adversary is trying to communicate with compromised systems to control them.",
            reference_url="https://attack.mitre.org/tactics/TA0011/",
        ),
        "TA0010": AttackTactic(
            tactic_id="TA0010",
            name="Exfiltration",
            description="The adversary is trying to steal data.",
            reference_url="https://attack.mitre.org/tactics/TA0010/",
        ),
        "TA0040": AttackTactic(
            tactic_id="TA0040",
            name="Impact",
            description="The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
            reference_url="https://attack.mitre.org/tactics/TA0040/",
        ),
    }

    # Curated Enterprise Techniques & Sub-techniques
    TECHNIQUES: dict[str, AttackTechnique] = {
        # Reconnaissance
        "T1595": AttackTechnique(
            technique_id="T1595",
            name="Active Scanning",
            tactic_ids=["TA0043"],
            description="Adversaries may execute active scans to gather information on IP blocks and ports.",
            data_sources=["Network Traffic: Network Traffic Flow", "Sensor Health: Host Status"],
            reference_url="https://attack.mitre.org/techniques/T1595/",
        ),
        "T1595.001": AttackTechnique(
            technique_id="T1595.001",
            name="Scanning IP Blocks",
            tactic_ids=["TA0043"],
            description="Adversaries may scan IP blocks to identify targets for future operations.",
            is_subtechnique=True,
            parent_id="T1595",
            data_sources=["Network Traffic: Network Traffic Flow"],
            reference_url="https://attack.mitre.org/techniques/T1595/001/",
        ),
        "T1595.002": AttackTechnique(
            technique_id="T1595.002",
            name="Vulnerability Scanning",
            tactic_ids=["TA0043"],
            description="Adversaries may scan for vulnerabilities in public-facing systems.",
            is_subtechnique=True,
            parent_id="T1595",
            data_sources=["Network Traffic: Network Traffic Flow"],
            reference_url="https://attack.mitre.org/techniques/T1595/002/",
        ),
        # Resource Development
        "T1587": AttackTechnique(
            technique_id="T1587",
            name="Develop Capabilities",
            tactic_ids=["TA0042"],
            description="Adversaries may build tools, exploits, or payloads to support operations.",
            reference_url="https://attack.mitre.org/techniques/T1587/",
        ),
        # Initial Access
        "T1190": AttackTechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_ids=["TA0001"],
            description="Adversaries may attempt to exploit vulnerabilities in Internet-facing software (web apps, SSH, VPN).",
            data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
        "T1566": AttackTechnique(
            technique_id="T1566",
            name="Phishing",
            tactic_ids=["TA0001"],
            description="Adversaries may send phishing messages to gain access to victim systems.",
            data_sources=["Application Log: Application Log Content", "File: File Creation"],
            reference_url="https://attack.mitre.org/techniques/T1566/",
        ),
        "T1078": AttackTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            data_sources=["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
            reference_url="https://attack.mitre.org/techniques/T1078/",
        ),
        # Execution
        "T1059": AttackTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic_ids=["TA0002"],
            description="Adversaries may abuse command and script interpreters to execute commands.",
            data_sources=["Process: Process Creation", "Command: Command Execution"],
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
        "T1059.001": AttackTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            tactic_ids=["TA0002"],
            description="Adversaries may abuse PowerShell commands and scripts for execution.",
            is_subtechnique=True,
            parent_id="T1059",
            data_sources=["Process: Process Creation", "Script: Script Execution"],
            reference_url="https://attack.mitre.org/techniques/T1059/001/",
        ),
        "T1059.003": AttackTechnique(
            technique_id="T1059.003",
            name="Windows Command Shell",
            tactic_ids=["TA0002"],
            description="Adversaries may abuse cmd.exe to execute commands.",
            is_subtechnique=True,
            parent_id="T1059",
            data_sources=["Process: Process Creation"],
            reference_url="https://attack.mitre.org/techniques/T1059/003/",
        ),
        "T1059.004": AttackTechnique(
            technique_id="T1059.004",
            name="Unix Shell",
            tactic_ids=["TA0002"],
            description="Adversaries may abuse Unix shells (sh, bash, zsh) to execute malicious commands.",
            is_subtechnique=True,
            parent_id="T1059",
            data_sources=["Process: Process Creation"],
            reference_url="https://attack.mitre.org/techniques/T1059/004/",
        ),
        # Persistence
        "T1505": AttackTechnique(
            technique_id="T1505",
            name="Server Software Component",
            tactic_ids=["TA0003"],
            description="Adversaries may abuse server software components to establish persistence.",
            reference_url="https://attack.mitre.org/techniques/T1505/",
        ),
        "T1505.003": AttackTechnique(
            technique_id="T1505.003",
            name="Web Shell",
            tactic_ids=["TA0003", "TA0002"],
            description="Adversaries may backdoor web servers by creating web shells.",
            is_subtechnique=True,
            parent_id="T1505",
            data_sources=["File: File Creation", "Process: Process Creation", "Network Traffic: Network Traffic Content"],
            reference_url="https://attack.mitre.org/techniques/T1505/003/",
        ),
        "T1053": AttackTechnique(
            technique_id="T1053",
            name="Scheduled Task/Job",
            tactic_ids=["TA0003", "TA0002", "TA0004"],
            description="Adversaries may abuse task scheduling functionality to execute programs at system startup or scheduled intervals.",
            data_sources=["Scheduled Job: Scheduled Job Creation"],
            reference_url="https://attack.mitre.org/techniques/T1053/",
        ),
        # Privilege Escalation
        "T1548": AttackTechnique(
            technique_id="T1548",
            name="Abuse Elevation Control Mechanism",
            tactic_ids=["TA0004", "TA0005"],
            description="Adversaries may circumvent mechanisms designed to control elevation of privileges.",
            reference_url="https://attack.mitre.org/techniques/T1548/",
        ),
        "T1548.003": AttackTechnique(
            technique_id="T1548.003",
            name="Sudo and Sudo Caching",
            tactic_ids=["TA0004", "TA0005"],
            description="Adversaries may abuse sudoers privileges or cached credentials to run commands with root privileges.",
            is_subtechnique=True,
            parent_id="T1548",
            data_sources=["Command: Command Execution", "Process: Process Creation"],
            reference_url="https://attack.mitre.org/techniques/T1548/003/",
        ),
        # Defense Evasion
        "T1027": AttackTechnique(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic_ids=["TA0005"],
            description="Adversaries may attempt to make an executable or script difficult to discover or analyze.",
            data_sources=["File: File Metadata", "Script: Script Execution"],
            reference_url="https://attack.mitre.org/techniques/T1027/",
        ),
        "T1070": AttackTechnique(
            technique_id="T1070",
            name="Indicator Removal",
            tactic_ids=["TA0005"],
            description="Adversaries may delete or modify artifacts generated on a system to remove evidence.",
            reference_url="https://attack.mitre.org/techniques/T1070/",
        ),
        # Credential Access
        "T1110": AttackTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic_ids=["TA0006"],
            description="Adversaries may use brute-force techniques to guess passwords or credentials.",
            data_sources=["User Account: User Account Authentication"],
            reference_url="https://attack.mitre.org/techniques/T1110/",
        ),
        "T1110.001": AttackTechnique(
            technique_id="T1110.001",
            name="Password Guessing",
            tactic_ids=["TA0006"],
            description="Adversaries may guess passwords to attempt to log in to accounts.",
            is_subtechnique=True,
            parent_id="T1110",
            data_sources=["User Account: User Account Authentication"],
            reference_url="https://attack.mitre.org/techniques/T1110/001/",
        ),
        "T1003": AttackTechnique(
            technique_id="T1003",
            name="OS Credential Dumping",
            tactic_ids=["TA0006"],
            description="Adversaries may dump credentials from the OS (LSASS memory, /etc/shadow).",
            data_sources=["Command: Command Execution", "Process: Process Access"],
            reference_url="https://attack.mitre.org/techniques/T1003/",
        ),
        "T1003.008": AttackTechnique(
            technique_id="T1003.008",
            name="/etc/passwd and /etc/shadow Access",
            tactic_ids=["TA0006"],
            description="Adversaries may dump Linux credentials by reading /etc/shadow or /etc/passwd.",
            is_subtechnique=True,
            parent_id="T1003",
            data_sources=["File: File Access", "Command: Command Execution"],
            reference_url="https://attack.mitre.org/techniques/T1003/008/",
        ),
        # Discovery
        "T1046": AttackTechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic_ids=["TA0007"],
            description="Adversaries may attempt to get a listing of services running on remote hosts.",
            data_sources=["Network Traffic: Network Traffic Flow"],
            reference_url="https://attack.mitre.org/techniques/T1046/",
        ),
        "T1082": AttackTechnique(
            technique_id="T1082",
            name="System Information Discovery",
            tactic_ids=["TA0007"],
            description="Adversaries may get detailed information about the operating system and hardware.",
            reference_url="https://attack.mitre.org/techniques/T1082/",
        ),
        # Lateral Movement
        "T1021": AttackTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic_ids=["TA0008"],
            description="Adversaries may log on to remote systems using valid credentials or remote management tools.",
            data_sources=["Network Traffic: Network Traffic Flow", "Logon Session: Logon Session Creation"],
            reference_url="https://attack.mitre.org/techniques/T1021/",
        ),
        "T1021.002": AttackTechnique(
            technique_id="T1021.002",
            name="SMB/Windows Admin Shares",
            tactic_ids=["TA0008"],
            description="Adversaries may abuse SMB admin shares (C$, ADMIN$) to move laterally.",
            is_subtechnique=True,
            parent_id="T1021",
            data_sources=["Network Traffic: Network Traffic Flow"],
            reference_url="https://attack.mitre.org/techniques/T1021/002/",
        ),
        # Collection
        "T1005": AttackTechnique(
            technique_id="T1005",
            name="Data from Local System",
            tactic_ids=["TA0009"],
            description="Adversaries may search for and gather sensitive files from a local system.",
            data_sources=["File: File Access"],
            reference_url="https://attack.mitre.org/techniques/T1005/",
        ),
        # Command and Control
        "T1071": AttackTechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic_ids=["TA0011"],
            description="Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS).",
            data_sources=["Network Traffic: Network Traffic Content"],
            reference_url="https://attack.mitre.org/techniques/T1071/",
        ),
        "T1071.004": AttackTechnique(
            technique_id="T1071.004",
            name="DNS",
            tactic_ids=["TA0011"],
            description="Adversaries may communicate using the DNS protocol for C2 or exfiltration tunneling.",
            is_subtechnique=True,
            parent_id="T1071",
            data_sources=["Network Traffic: Network Traffic Content"],
            reference_url="https://attack.mitre.org/techniques/T1071/004/",
        ),
        # Exfiltration
        "T1041": AttackTechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic_ids=["TA0010"],
            description="Adversaries may steal data by transferring it over an existing C2 channel.",
            data_sources=["Network Traffic: Network Traffic Flow"],
            reference_url="https://attack.mitre.org/techniques/T1041/",
        ),
        "T1048": AttackTechnique(
            technique_id="T1048",
            name="Exfiltration Over Alternative Protocol",
            tactic_ids=["TA0010"],
            description="Adversaries may steal data by transferring it over an alternative network protocol (DNS, ICMP).",
            reference_url="https://attack.mitre.org/techniques/T1048/",
        ),
        # Impact
        "T1486": AttackTechnique(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            tactic_ids=["TA0040"],
            description="Adversaries may encrypt data on target systems to interrupt system availability (Ransomware).",
            data_sources=["File: File Modification"],
            reference_url="https://attack.mitre.org/techniques/T1486/",
        ),
        "T1489": AttackTechnique(
            technique_id="T1489",
            name="Service Stop",
            tactic_ids=["TA0040"],
            description="Adversaries may stop or disable services to render systems inoperable.",
            reference_url="https://attack.mitre.org/techniques/T1489/",
        ),
    }


class AttackMappingEngine:
    """Deterministic MITRE ATT&CK Mapping and Heatmap Engine."""

    RULE_TECHNIQUE_MAP: dict[str, list[tuple[str, str, float]]] = {
        # Detection Rule ID -> list of (Technique ID, Primary Tactic ID, Confidence)
        "SEC-AUTH-001": [("T1110.001", "TA0006", 0.90), ("T1110", "TA0006", 0.95)],
        "SEC-AUTH-002": [("T1078", "TA0001", 0.88), ("T1110", "TA0006", 0.85)],
        "SEC-PROC-001": [("T1059.001", "TA0002", 0.95), ("T1027", "TA0005", 0.85)],
        "SEC-PROC-002": [("T1505.003", "TA0003", 0.95), ("T1059.003", "TA0002", 0.85), ("T1059.004", "TA0002", 0.85)],
        "SEC-WEB-001": [("T1190", "TA0001", 0.92)],
        "SEC-NET-001": [("T1071.004", "TA0011", 0.85), ("T1048", "TA0010", 0.80)],
        "SEC-HASH-001": [("T1059", "TA0002", 0.80), ("T1505.003", "TA0003", 0.85)],
    }

    @classmethod
    def get_tactics(cls) -> list[dict[str, Any]]:
        """Returns ordered list of all 14 Enterprise Tactics."""
        return [
            {
                "tactic_id": t.tactic_id,
                "name": t.name,
                "description": t.description,
                "reference_url": t.reference_url,
            }
            for t in AttackCatalog.TACTICS.values()
        ]

    @classmethod
    def get_techniques(cls, tactic_id: str | None = None) -> list[dict[str, Any]]:
        """Returns catalog techniques, optionally filtered by tactic."""
        results = []
        for t in AttackCatalog.TECHNIQUES.values():
            if tactic_id and tactic_id not in t.tactic_ids:
                continue
            results.append({
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic_ids": t.tactic_ids,
                "description": t.description,
                "is_subtechnique": t.is_subtechnique,
                "parent_id": t.parent_id,
                "data_sources": t.data_sources,
                "reference_url": t.reference_url,
            })
        return results

    @classmethod
    def map_alert(cls, alert: Any) -> list[TechniqueMapping]:
        """Maps a SOCAlert object to corresponding ATT&CK techniques."""
        rule_id = getattr(alert, "rule_id", "")
        title = getattr(alert, "title", "")
        alert_id = getattr(alert, "alert_id", "")
        source_ip = getattr(alert, "target_ip", "") or getattr(alert, "target_host", "unknown")
        ev_ids = getattr(alert, "matched_event_ids", [])

        mappings: list[TechniqueMapping] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if rule_id in cls.RULE_TECHNIQUE_MAP:
            for tech_id, tac_id, conf in cls.RULE_TECHNIQUE_MAP[rule_id]:
                tech = AttackCatalog.TECHNIQUES.get(tech_id)
                tac = AttackCatalog.TACTICS.get(tac_id)
                if tech and tac:
                    mappings.append(
                        TechniqueMapping(
                            mapping_id=f"map-{tech_id}-{alert_id[:8]}",
                            technique_id=tech_id,
                            technique_name=tech.name,
                            tactic_id=tac_id,
                            tactic_name=tac.name,
                            confidence=conf,
                            match_rule_id=rule_id,
                            match_reason=f"Alert '{title}' matched signature rule {rule_id}",
                            source_entity=source_ip,
                            evidence_ids=ev_ids,
                            timestamp=now_iso,
                        )
                    )
        return mappings

    @classmethod
    def map_event(cls, event: Any) -> list[TechniqueMapping]:
        """Maps a UniversalSecurityEvent to ATT&CK techniques using pattern heuristics."""
        mappings: list[TechniqueMapping] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        ev_id = getattr(event, "event_id", "")
        cmd = getattr(event, "command_line", "") or ""
        url = getattr(event, "url", "") or ""
        proc = (getattr(event, "process_name", "") or "").lower()
        parent = (getattr(event, "parent_process", "") or "").lower()
        src = getattr(event, "source_ip", "") or getattr(event, "hostname", "unknown")

        # PowerShell obfuscation
        if "powershell" in proc or "pwsh" in proc or "powershell" in cmd.lower():
            if any(f in cmd.lower() for f in ["-enc", "-encodedcommand", "bypass", "-w hidden"]):
                tech = AttackCatalog.TECHNIQUES["T1059.001"]
                tac = AttackCatalog.TACTICS["TA0002"]
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map-T1059.001-{ev_id[:8]}",
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        tactic_id=tac.tactic_id,
                        tactic_name=tac.name,
                        confidence=0.92,
                        match_rule_id="HEUR-PS-OBFUSCATION",
                        match_reason=f"PowerShell executed with obfuscation / bypass flags: {cmd[:80]}",
                        source_entity=src,
                        evidence_ids=[ev_id],
                        timestamp=now_iso,
                    )
                )

        # Web Server Spawning Shell
        web_daemons = {"w3wp", "httpd", "nginx", "apache2", "tomcat"}
        shells = {"cmd.exe", "powershell.exe", "sh", "bash", "zsh"}
        if any(w in parent for w in web_daemons) and any(s in proc for s in shells):
            tech = AttackCatalog.TECHNIQUES["T1505.003"]
            tac = AttackCatalog.TACTICS["TA0003"]
            mappings.append(
                TechniqueMapping(
                    mapping_id=f"map-T1505.003-{ev_id[:8]}",
                    technique_id=tech.technique_id,
                    technique_name=tech.name,
                    tactic_id=tac.tactic_id,
                    tactic_name=tac.name,
                    confidence=0.96,
                    match_rule_id="HEUR-WEB-SHELL",
                    match_reason=f"Web server daemon {parent} spawned shell interpreter {proc}",
                    source_entity=src,
                    evidence_ids=[ev_id],
                    timestamp=now_iso,
                )
            )

        # Sudo execution
        action = getattr(event, "event_action", "")
        if action == "sudo_execution" or "sudo " in cmd.lower():
            tech = AttackCatalog.TECHNIQUES["T1548.003"]
            tac = AttackCatalog.TACTICS["TA0004"]
            mappings.append(
                TechniqueMapping(
                    mapping_id=f"map-T1548.003-{ev_id[:8]}",
                    technique_id=tech.technique_id,
                    technique_name=tech.name,
                    tactic_id=tac.tactic_id,
                    tactic_name=tac.name,
                    confidence=0.90,
                    match_rule_id="HEUR-SUDO-ELEVATION",
                    match_reason=f"Execution of elevated command via sudo: {cmd[:80]}",
                    source_entity=src,
                    evidence_ids=[ev_id],
                    timestamp=now_iso,
                )
            )

        # Web attack (SQLi / Traversal)
        if url:
            url_low = url.lower()
            if any(p in url_low for p in ["union select", "1=1", "sleep(", "../", "..\\", "etc/passwd", "win.ini"]):
                tech = AttackCatalog.TECHNIQUES["T1190"]
                tac = AttackCatalog.TACTICS["TA0001"]
                mappings.append(
                    TechniqueMapping(
                        mapping_id=f"map-T1190-{ev_id[:8]}",
                        technique_id=tech.technique_id,
                        technique_name=tech.name,
                        tactic_id=tac.tactic_id,
                        tactic_name=tac.name,
                        confidence=0.88,
                        match_rule_id="HEUR-WEB-EXPLOIT",
                        match_reason=f"Web exploit attempt in HTTP request: {url[:80]}",
                        source_entity=src,
                        evidence_ids=[ev_id],
                        timestamp=now_iso,
                    )
                )

        return mappings

    @classmethod
    def build_matrix(cls, mappings: list[TechniqueMapping]) -> AttackMatrixCoverage:
        """Constructs an ATT&CK Matrix coverage heatmap across all 14 tactics."""
        # Initialize tactics bucket
        breakdown: dict[str, dict[str, Any]] = {}
        for tac_id, tac in AttackCatalog.TACTICS.items():
            breakdown[tac_id] = {
                "tactic_id": tac_id,
                "name": tac.name,
                "mapped_count": 0,
                "techniques": {},
                "max_confidence": 0.0,
            }

        unique_techs: set[str] = set()

        for m in mappings:
            unique_techs.add(m.technique_id)
            tac_bucket = breakdown.get(m.tactic_id)
            if tac_bucket is not None:
                tac_bucket["mapped_count"] += 1
                if m.confidence > tac_bucket["max_confidence"]:
                    tac_bucket["max_confidence"] = m.confidence
                
                tech_dict = tac_bucket["techniques"].setdefault(m.technique_id, {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "hit_count": 0,
                    "confidence": m.confidence,
                    "matched_reasons": [],
                    "evidence_ids": [],
                })
                tech_dict["hit_count"] += 1
                tech_dict["confidence"] = max(tech_dict["confidence"], m.confidence)
                if m.match_reason not in tech_dict["matched_reasons"]:
                    tech_dict["matched_reasons"].append(m.match_reason)
                for eid in m.evidence_ids:
                    if eid not in tech_dict["evidence_ids"]:
                        tech_dict["evidence_ids"].append(eid)

        total_tactics = len(AttackCatalog.TACTICS)
        covered_tactics = sum(1 for b in breakdown.values() if b["mapped_count"] > 0)
        coverage_pct = round((covered_tactics / total_tactics) * 100.0, 2)

        # High-risk techniques (confidence >= 0.85)
        high_risk = []
        for tac_id, b in breakdown.items():
            for t_id, t_info in b["techniques"].items():
                if t_info["confidence"] >= 0.85:
                    high_risk.append({
                        "tactic_id": tac_id,
                        "tactic_name": b["name"],
                        "technique_id": t_id,
                        "technique_name": t_info["technique_name"],
                        "confidence": t_info["confidence"],
                        "hit_count": t_info["hit_count"],
                    })

        return AttackMatrixCoverage(
            total_tactics=total_tactics,
            covered_tactics=covered_tactics,
            coverage_percentage=coverage_pct,
            total_techniques_mapped=len(unique_techs),
            tactics_breakdown=breakdown,
            high_risk_techniques=high_risk,
        )

    @classmethod
    def export_matrix_markdown(cls, coverage: AttackMatrixCoverage) -> str:
        """Formats the ATT&CK Matrix coverage as an executive Markdown report table."""
        lines = [
            "# REDLOOP MITRE ATT&CK Matrix Coverage Report",
            f"**Generated:** {coverage.generated_at} UTC",
            f"**Coverage:** {coverage.covered_tactics} / {coverage.total_tactics} tactics ({coverage.coverage_percentage}%)",
            f"**Total Techniques Mapped:** {coverage.total_techniques_mapped}",
            "",
            "## 1. Tactic Coverage Summary",
            "",
            "| Tactic ID | Tactic Name | Mapped Techniques | Max Confidence | Coverage Status |",
            "|:---|:---|:---:|:---:|:---|",
        ]

        for tac_id, b in coverage.tactics_breakdown.items():
            status = "🟢 COVERED" if b["mapped_count"] > 0 else "⚪ UNCOVERED"
            lines.append(
                f"| `{tac_id}` | **{b['name']}** | {b['mapped_count']} | {b['max_confidence']:.2f} | {status} |"
            )

        lines.extend([
            "",
            "## 2. High-Confidence Observed Techniques",
            "",
            "| Technique ID | Technique Name | Tactic | Confidence | Hit Count |",
            "|:---|:---|:---|:---:|:---:|",
        ])

        if coverage.high_risk_techniques:
            for hr in coverage.high_risk_techniques:
                lines.append(
                    f"| `{hr['technique_id']}` | **{hr['technique_name']}** | {hr['tactic_name']} | {hr['confidence']:.2f} | {hr['hit_count']} |"
                )
        else:
            lines.append("| *None* | *No high-confidence techniques mapped* | - | - | - |")

        lines.append("")
        return "\n".join(lines)
