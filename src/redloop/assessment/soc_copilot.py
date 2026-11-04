"""Autonomous Copilot SOC Investigation & Triage Engine (Phase 5).

Provides autonomous investigation workflows:
1. Understand user request & extract target entities (IPs, domains, accounts, hashes, CVEs)
2. Inspect local telemetry, findings, and events
3. Autonomous tool & playbook selection (passive triage, banner verify, IOC correlation)
4. Correlate alerts into investigation timelines
5. Perform gap analysis (missing evidence, unverified assumptions)
6. Generate audit-grade technical incident investigation reports
7. Enforce lifecycle states (PLANNING, RUNNING, COMPLETED, WAITING_FOR_APPROVAL, etc.)
8. Grounded answers: NO_MATCHING_TELEMETRY on missing data, conceptual answers on general cyber questions.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from redloop.assessment.finding_models import FindingStore
from redloop.assessment.intel_engine import VulnerabilityIntelligenceEngine
from redloop.assessment.soc_detection import SOCAlert, SOCDetectionEngine
from redloop.assessment.soc_events import EventCategory, EventSeverity, UniversalSecurityEvent
from redloop.assessment.soc_playbooks import SOCPlaybookEngine
from redloop.assessment.soc_timeline import (
    EvidenceObservationClass,
    IncidentRelationType,
    SOCIncident,
    SOCIncidentCorrelator,
    SOCTimelineEngine,
    SOCTimelineItem,
)


class InvestigationLifecycleState(str, Enum):
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    BLOCKED = "BLOCKED"
    NO_MATCHING_TELEMETRY = "NO_MATCHING_TELEMETRY"


@dataclass
class InvestigationTask:
    investigation_id: str
    user_query: str
    target_entity: str
    state: InvestigationLifecycleState = InvestigationLifecycleState.PLANNING
    telemetry_status: str = "MATCHING_TELEMETRY"
    extracted_indicators: list[str] = field(default_factory=list)
    incident: SOCIncident | None = None
    timeline: list[SOCTimelineItem] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    findings_summary: str = ""
    recommended_playbook_id: str | None = None
    confidence_score: float = 0.85
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now_iso
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "user_query": self.user_query,
            "target_entity": self.target_entity,
            "state": self.state.value if hasattr(self.state, "value") else str(self.state),
            "telemetry_status": self.telemetry_status,
            "extracted_indicators": self.extracted_indicators,
            "incident": self.incident.to_dict() if self.incident else None,
            "timeline": [t.to_dict() for t in self.timeline],
            "missing_evidence": self.missing_evidence,
            "findings_summary": self.findings_summary,
            "recommended_playbook_id": self.recommended_playbook_id,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# Knowledge base of general cybersecurity concepts for target-less conceptual queries
_CYBER_KNOWLEDGE_BASE: dict[str, dict[str, str]] = {
    "dns_tunneling": {
        "title": "DNS Tunneling Overview & Detection",
        "concept": "DNS tunneling encodes non-DNS protocols into DNS queries and responses (often TXT, NULL, or CNAME records) to bypass firewalls and captive portals for command-and-control or data exfiltration.",
        "detection": "Detection relies on high query frequency, anomalous query length, high entropy in subdomains, and uncommon record types queried to specific unrated authoritative nameservers.",
        "defense": "Deploy DNS inspection, response policy zones (RPZ), query length caps, and restrict internal resolver egress exclusively to approved recursive resolvers.",
    },
    "sql_injection": {
        "title": "SQL Injection (SQLi) Overview & Remediation",
        "concept": "SQL injection occurs when untrusted user input is directly concatenated or interpolated into dynamic database queries, altering the structure of the executed SQL command.",
        "detection": "WAF signatures detecting SQL meta-characters (UNION SELECT, OR 1=1, comment delimiters '--'), database error monitoring, and anomalous query timing/payload lengths.",
        "defense": "Use parameterized queries (prepared statements), object-relational mappers (ORMs), strict input whitelisting, and least-privilege database user accounts.",
    },
    "path_traversal": {
        "title": "Path Traversal / Directory Traversal Overview",
        "concept": "Path traversal exploits allow adversaries to read or write arbitrary files on the server by supplying relative directory navigation sequences (e.g., '../', '..\\', or URL-encoded equivalents like '%2e%2e%2f').",
        "detection": "Log inspection for repetitive dot-dot-slash patterns, canonical path verification anomalies, and unauthorized access to system files (/etc/passwd, win.ini).",
        "defense": "Validate input against a strict whitelist, resolve and compare canonical file paths (os.path.realpath) against an allowed base directory, and avoid direct user-controlled file paths.",
    },
    "brute_force": {
        "title": "Brute-Force & Credential Stuffing Attacks",
        "concept": "Automated attempts to guess valid authentication credentials by systematically trying numerous passwords against known usernames (brute-force) or testing leaked credential pairs across multiple services (credential stuffing).",
        "detection": "High rates of Event ID 4625 / Linux pam_unix auth failures, multiple usernames from a single source IP, or single username targeted from distributed IPs (password spraying).",
        "defense": "Implement rate limiting, account lockout policies, multi-factor authentication (MFA/FIDO2), CAPTCHA, and continuous monitoring of authentication logs.",
    },
    "powershell_obfuscation": {
        "title": "Malicious PowerShell & Obfuscation Techniques",
        "concept": "Adversaries leverage PowerShell for living-off-the-land (LotL) execution, using base64 encoded commands (-EncodedCommand / -enc), execution policy bypasses (-ep bypass), and obfuscated string concatenation.",
        "detection": "Monitor Windows Event 4688 with process command line auditing, Event 4104 (Script Block Logging), and AMSI (Antimalware Scan Interface) alerts.",
        "defense": "Enforce PowerShell Constrained Language Mode, AppLocker/WDAC script enforcement, centralized Script Block Logging, and behavioral endpoint detection.",
    },
}


class SOCCopilotEngine:
    """Autonomous Copilot SOC Investigation Engine."""

    _active_investigations: dict[str, InvestigationTask] = {}

    @classmethod
    def start_investigation(
        cls,
        user_query: str,
        events: list[UniversalSecurityEvent] | None = None,
        alerts: list[SOCAlert] | None = None,
        explicit_target: str | None = None,
    ) -> InvestigationTask:
        """Launches an autonomous SOC investigation from a natural language request."""
        inv_id = f"inv-{uuid.uuid4().hex[:8]}"

        # 1. Indicator & Target Extraction
        extracted_indicators: list[str] = []
        if explicit_target:
            extracted_indicators.append(explicit_target.strip())

        # Hostname extraction after keyword (host, endpoint, machine, server)
        host_matches = re.findall(r"\b(?:host|server|device|machine|endpoint|target|box)\s+([a-zA-Z0-9_.-]+)\b", user_query, re.IGNORECASE)
        for hm in host_matches:
            if hm not in extracted_indicators and not hm.lower().endswith((".exe", ".dll", ".ps1")):
                extracted_indicators.append(hm)

        # Common server naming conventions (e.g. WEB-PROD-01, DB-SEC-02)
        naming_matches = re.findall(r"\b[A-Za-z0-9]+-[A-Za-z0-9_-]+\b", user_query)
        for nm in naming_matches:
            if not nm.startswith(("ALT-", "INC-", "EVT-", "FIND-", "CVE-", "PB-", "SEC-")):
                if nm not in extracted_indicators:
                    extracted_indicators.append(nm)

        # Regex extraction from user_query for IPs
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_query)
        for ip in ip_matches:
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                if ip not in extracted_indicators:
                    extracted_indicators.append(ip)

        # Domains
        domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", user_query)
        for dom in domain_matches:
            if dom not in extracted_indicators and not dom.lower().endswith((".exe", ".dll", ".ps1", ".sh", ".bat")):
                extracted_indicators.append(dom)

        # CVEs
        cve_matches = re.findall(r"\bCVE-\d{4}-\d{4,}\b", user_query, re.IGNORECASE)
        for cve in cve_matches:
            cve_up = cve.upper()
            if cve_up not in extracted_indicators:
                extracted_indicators.append(cve_up)

        # Hashes
        hash_matches = re.findall(r"\b[a-fA-F0-9]{32,64}\b", user_query)
        for h in hash_matches:
            if h not in extracted_indicators:
                extracted_indicators.append(h)

        # Alert / Incident ID matches
        id_matches = re.findall(r"\b(?:ALT|INC|EVT|FIND)-[a-zA-Z0-9_-]+\b", user_query, re.IGNORECASE)
        for i_m in id_matches:
            if i_m not in extracted_indicators:
                extracted_indicators.append(i_m)

        # 2. Check for General Cybersecurity Knowledge Query
        is_general_query = False
        query_lower = user_query.strip().lower()

        general_indicators = [
            "what is", "how does", "how do", "why does", "explain", "describe",
            "define", "difference between", "tell me about", "overview of",
            "best practice", "mitre att&ck", "zero trust"
        ]
        if not explicit_target and (not extracted_indicators or any(query_lower.startswith(gi) for gi in general_indicators)):
            is_general_query = any(k in query_lower for k in [
                "dns tunneling", "sql injection", "sqli", "path traversal", "directory traversal",
                "brute force", "credential stuffing", "powershell", "obfuscation", "lateral movement",
                "zero trust", "defense in depth", "cve", "cvss", "epss"
            ]) or any(query_lower.startswith(gi) for gi in general_indicators)

        if is_general_query and not explicit_target:
            return cls._handle_general_query(inv_id, user_query)

        # 3. Target Scope Resolution
        primary_target = explicit_target or (extracted_indicators[0] if extracted_indicators else None)

        if not primary_target:
            scoped_events = list(events or [])
            scoped_alerts = list(alerts or [])
            primary_target = "TelemetryScope"
        else:
            targets_set = set(extracted_indicators)
            scoped_events = [
                e for e in (events or [])
                if (e.source_ip in targets_set)
                or (e.destination_ip in targets_set)
                or (e.hostname in targets_set)
                or (e.domain in targets_set)
                or (e.file_hash in targets_set)
                or (e.username in targets_set)
                or (e.event_id in targets_set)
            ]
            scoped_alerts = [
                a for a in (alerts or [])
                if (a.target_ip in targets_set)
                or (a.target_host in targets_set)
                or (a.target_user in targets_set)
                or (a.alert_id in targets_set)
                or any(ind in targets_set for ind in a.context_indicators.values() if isinstance(ind, str))
            ]

        # 4. Handle Missing Data
        if primary_target != "TelemetryScope" and not scoped_events and not scoped_alerts:
            return cls._handle_missing_data(inv_id, user_query, primary_target, extracted_indicators)

        # 5. Correlate Incidents & Build Timeline
        incidents = SOCIncidentCorrelator.correlate_alerts(scoped_alerts, scoped_events)
        primary_incident = incidents[0] if incidents else None
        timeline = SOCTimelineEngine.build_timeline(events=scoped_events, alerts=scoped_alerts)

        # 6. Gap Analysis & Threat Scenario Intelligence
        missing_evidence: list[str] = []
        if not scoped_events:
            missing_evidence.append("Raw host/network telemetry logs not ingested for target entity.")

        summary_lines: list[str] = [
            f"Autonomous SOC Copilot triaged investigation for target '{primary_target}'.",
            f"Analyzed {len(scoped_events)} security events and {len(scoped_alerts)} alerts.",
        ]

        has_auth_events = any(e.event_action in ("logon_failure", "logon_failed", "logon_success") for e in scoped_events) or any(a.rule_id.startswith("SEC-AUTH") for a in scoped_alerts)
        has_proc_events = any(e.event_action in ("process_create", "process_execution") for e in scoped_events) or any(a.rule_id.startswith("SEC-PROC") for a in scoped_alerts)
        has_web_events = any(e.event_category == EventCategory.WEB for e in scoped_events) or any(a.rule_id.startswith("SEC-WEB") for a in scoped_alerts)
        has_dns_events = any(e.event_category == EventCategory.DNS for e in scoped_events) or any(a.rule_id.startswith("SEC-DNS") for a in scoped_alerts)

        # Threat Scenario 1: Brute-Force / Credential Stuffing
        if has_auth_events or "brute" in query_lower or "credential" in query_lower or "logon" in query_lower:
            fail_count = sum(1 for e in scoped_events if e.event_action in ("logon_failure", "logon_failed"))
            succ_count = sum(1 for e in scoped_events if e.event_action == "logon_success")
            summary_lines.append(f"Authentication activity: {fail_count} failed logon attempts, {succ_count} successful logons.")
            lateral_ev = [e for e in scoped_events if (e.event_category == EventCategory.NETWORK and "lateral" in (e.event_action or "").lower()) or e.event_action in ("smb_access", "rdp_session", "lateral_movement")]
            if lateral_ev:
                summary_lines.append(f"Corroborated lateral movement detected via {len(lateral_ev)} sessions.")
            else:
                summary_lines.append("No lateral movement observed in current telemetry evidence.")
            if not succ_count:
                missing_evidence.append("Telemetry lacks post-brute-force authentication window to verify account compromise.")

        # Threat Scenario 2: Suspicious PowerShell
        if has_proc_events or "powershell" in query_lower:
            ps_events = [e for e in scoped_events if "powershell" in (e.command_line or "").lower() or "powershell" in (e.process_name or "").lower()]
            encoded_flags = [e for e in ps_events if any(f in (e.command_line or "").lower() for f in ("-enc", "-encodedcommand", "-ep bypass", "-nop", "-w hidden"))]
            if encoded_flags:
                summary_lines.append(f"Identified {len(encoded_flags)} process executions with obfuscation/bypass flags (-enc/-ep bypass/-nop).")
            missing_evidence.append("Parent process lineage and subsequent outbound network connections require verification.")
            missing_evidence.append("Decoded PowerShell script block log (Windows Event ID 4104) recommended.")

        # Threat Scenario 3: Web Attack (SQLi vs Path Traversal)
        if has_web_events or "sqli" in query_lower or "traversal" in query_lower or "web attack" in query_lower:
            traversal_alerts = [a for a in scoped_alerts if a.rule_id == "SEC-WEB-002" or "traversal" in a.title.lower()]
            sqli_alerts = [a for a in scoped_alerts if a.rule_id == "SEC-WEB-001" or "sql" in a.title.lower()]
            if traversal_alerts:
                summary_lines.append(f"Detected Path Traversal attempts ({len(traversal_alerts)} alerts).")
            if sqli_alerts:
                summary_lines.append(f"Detected SQL Injection attempts ({len(sqli_alerts)} alerts).")
            summary_lines.append("Database compromise is NOT corroborated without backend database query execution logs.")
            missing_evidence.append("Backend database audit logs and application error traces required to corroborate compromise.")

        # Threat Scenario 4: DNS Tunneling
        if has_dns_events or "dns tunneling" in query_lower or "dns" in query_lower:
            dns_alerts = [a for a in scoped_alerts if a.rule_id == "SEC-DNS-001" or "dns" in a.title.lower()]
            if dns_alerts:
                summary_lines.append(f"High-frequency/high-entropy DNS query patterns identified ({len(dns_alerts)} alerts).")
                for da in dns_alerts[:2]:
                    dom = da.context_indicators.get("domain") or da.context_indicators.get("high_query_domain")
                    if dom:
                        summary_lines.append(f"Suspected tunneling apex domain: {dom}.")

        # Evidence-based query citation
        for ind in extracted_indicators:
            for ev in scoped_events:
                if ev.event_id == ind:
                    summary_lines.append(f"Cited Event: {ev.event_id} ({ev.event_name}) | SHA256: {ev.evidence_hash} | Severity: {ev.severity.value}.")
            for al in scoped_alerts:
                if al.alert_id == ind:
                    summary_lines.append(f"Cited Alert: {al.alert_id} ({al.title}) | Rule: {al.rule_id} | Confidence: {al.confidence:.0%}.")

        # 7. Playbook Selection
        recommended_playbook = "PB-MALWARE"
        if primary_incident and primary_incident.recommended_playbook_id:
            recommended_playbook = primary_incident.recommended_playbook_id
        elif any(a.rule_id == "SEC-AUTH-001" for a in scoped_alerts) or "brute" in query_lower:
            recommended_playbook = "PB-BRUTE"
        elif any(a.rule_id == "SEC-AUTH-002" for a in scoped_alerts) or "credential" in query_lower:
            recommended_playbook = "PB-CRED"
        elif any(a.rule_id.startswith("SEC-WEB") for a in scoped_alerts) or has_web_events:
            recommended_playbook = "PB-WEB"
        elif any(a.rule_id.startswith("SEC-PROC") for a in scoped_alerts) or has_proc_events:
            recommended_playbook = "PB-PSHELL"
        elif any(a.rule_id.startswith("SEC-DNS") for a in scoped_alerts) or has_dns_events:
            recommended_playbook = "PB-OUTBOUND"

        summary_lines.append(f"Recommended response workflow: Playbook {recommended_playbook} (Requires human authorization).")

        task = InvestigationTask(
            investigation_id=inv_id,
            user_query=user_query,
            target_entity=primary_target,
            state=InvestigationLifecycleState.COMPLETED,
            telemetry_status="MATCHING_TELEMETRY",
            extracted_indicators=list(set(extracted_indicators)),
            incident=primary_incident,
            timeline=timeline,
            missing_evidence=missing_evidence,
            findings_summary=" ".join(summary_lines),
            recommended_playbook_id=recommended_playbook,
            confidence_score=0.92 if primary_incident else 0.75,
        )

        cls._active_investigations[inv_id] = task
        return task

    @classmethod
    def _handle_general_query(cls, inv_id: str, user_query: str) -> InvestigationTask:
        """Handles conceptual cybersecurity questions without executing tools or inheriting targets."""
        q_lower = user_query.lower()
        matched_topic = None

        if "dns" in q_lower and "tunnel" in q_lower:
            matched_topic = _CYBER_KNOWLEDGE_BASE["dns_tunneling"]
        elif "sql" in q_lower or "injection" in q_lower or "sqli" in q_lower:
            matched_topic = _CYBER_KNOWLEDGE_BASE["sql_injection"]
        elif "path traversal" in q_lower or "directory traversal" in q_lower:
            matched_topic = _CYBER_KNOWLEDGE_BASE["path_traversal"]
        elif "brute force" in q_lower or "credential stuffing" in q_lower:
            matched_topic = _CYBER_KNOWLEDGE_BASE["brute_force"]
        elif "powershell" in q_lower or "obfuscat" in q_lower:
            matched_topic = _CYBER_KNOWLEDGE_BASE["powershell_obfuscation"]

        if matched_topic:
            summary = (
                f"### {matched_topic['title']}\n\n"
                f"**Mechanism:** {matched_topic['concept']}\n\n"
                f"**Detection Engineering:** {matched_topic['detection']}\n\n"
                f"**Remediation & Hardening:** {matched_topic['defense']}"
            )
        else:
            summary = (
                f"RedLoop Cybersecurity Copilot Conceptual Knowledge Response:\n"
                f"Your query '{user_query}' was processed as a general informational request. "
                "No target was specified, no active assessment tools were executed, and no prior session targets were inherited."
            )

        task = InvestigationTask(
            investigation_id=inv_id,
            user_query=user_query,
            target_entity="N/A (General Conceptual Query)",
            state=InvestigationLifecycleState.COMPLETED,
            telemetry_status="NOT_APPLICABLE",
            extracted_indicators=[],
            incident=None,
            timeline=[],
            missing_evidence=[],
            findings_summary=summary,
            recommended_playbook_id=None,
            confidence_score=1.0,
        )
        cls._active_investigations[inv_id] = task
        return task

    @classmethod
    def _handle_missing_data(
        cls,
        inv_id: str,
        user_query: str,
        primary_target: str,
        extracted_indicators: list[str],
    ) -> InvestigationTask:
        """Handles queries targeting entities with NO ingested telemetry."""
        missing_evidence = [
            "Raw host/network telemetry logs not ingested for target entity.",
            "Host process execution telemetry (Sysmon / Auditd / EDR) required.",
            "Authentication audit logs (Windows Event 4624/4625 / Linux auth.log) required.",
            "Perimeter network and firewall/flow logs (Zeek / Suricata / WAF) required.",
        ]
        summary = (
            f"NO_MATCHING_TELEMETRY: No ingested security events or alerts match target '{primary_target}'. "
            "Security posture cannot be evaluated without raw telemetry. "
            "RedLoop strictly avoids fabricating benign status when data is missing."
        )

        task = InvestigationTask(
            investigation_id=inv_id,
            user_query=user_query,
            target_entity=primary_target,
            state=InvestigationLifecycleState.NO_MATCHING_TELEMETRY,
            telemetry_status="NO_MATCHING_TELEMETRY",
            extracted_indicators=list(set(extracted_indicators)),
            incident=None,
            timeline=[],
            missing_evidence=missing_evidence,
            findings_summary=summary,
            recommended_playbook_id=None,
            confidence_score=0.0,
        )
        cls._active_investigations[inv_id] = task
        return task

    @classmethod
    def get_investigation(cls, investigation_id: str) -> InvestigationTask | None:
        return cls._active_investigations.get(investigation_id)

    @classmethod
    def generate_investigation_report(cls, investigation_id: str, format: str = "json") -> str | dict[str, Any]:
        """Generates audit-grade investigation report in JSON, Markdown, or HTML."""
        task = cls.get_investigation(investigation_id)
        if not task:
            return {"error": f"Investigation '{investigation_id}' not found."}

        report_dict = {
            "report_id": f"soc-rep-{task.investigation_id}",
            "schema_version": "5.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "investigation_id": task.investigation_id,
            "target_entity": task.target_entity,
            "user_query": task.user_query,
            "state": task.state.value if hasattr(task.state, "value") else str(task.state),
            "telemetry_status": task.telemetry_status,
            "confidence_score": task.confidence_score,
            "indicators": task.extracted_indicators,
            "missing_evidence": task.missing_evidence,
            "findings_summary": task.findings_summary,
            "recommended_playbook": task.recommended_playbook_id,
            "incident": task.incident.to_dict() if task.incident else None,
            "timeline_events_count": len(task.timeline),
        }

        if format.lower() in ("markdown", "md"):
            md_lines = [
                f"# REDLOOP SOC Investigation Report: `{task.target_entity}`",
                f"**Investigation ID:** `{task.investigation_id}` | **Status:** `{task.state.value}` | **Telemetry:** `{task.telemetry_status}` | **Confidence:** `{task.confidence_score:.0%}`  ",
                f"**Generated:** `{report_dict['generated_at']}`  ",
                "",
                "---",
                "",
                "## 1. Executive Incident Summary",
                f"{task.findings_summary}",
                "",
                "## 2. Target Indicators of Compromise (IOCs)",
            ]
            if task.extracted_indicators:
                for ind in task.extracted_indicators:
                    md_lines.append(f"- `{ind}`")
            else:
                md_lines.append("*(No specific external IOCs identified)*")

            md_lines.extend([
                "",
                "## 3. Evidence Gaps & Missing Information",
            ])
            if task.missing_evidence:
                for gap in task.missing_evidence:
                    md_lines.append(f"- [GAP] {gap}")
            else:
                md_lines.append("No critical evidence gaps identified.")

            md_lines.extend([
                "",
                "## 4. Response & Containment Playbook",
                f"**Assigned Playbook:** `{task.recommended_playbook_id or 'None (Informational / Missing Data)'}`",
                "*(Approval required before executing state-changing network or host changes)*",
                "",
            ])
            return "\n".join(md_lines)

        return report_dict

    @classmethod
    def handle_operational_query(
        cls,
        user_query: str,
        incident_id: str | None = None,
        alert_id: str | None = None,
        entity_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Operational Copilot Query Handler (Phase 9 B8).

        Handles autonomous SOC operational commands:
        - 'Investigate this incident'
        - 'Show evidence behind alert'
        - 'Find related events'
        - 'Explain attack sequence'
        - 'Recommend next step'
        - 'Prepare containment plan'
        - 'Verify endpoint isolated'

        Grounded responses citing evidence IDs, alert IDs, hash values, timestamps.
        """
        q_lower = user_query.strip().lower()
        ctx = context or {}

        # 1. Intent Classification
        intent = "unknown"
        if any(k in q_lower for k in ("investigate incident", "investigate this incident", "triage incident", "analyze incident")):
            intent = "investigate_incident"
        elif any(k in q_lower for k in ("show evidence", "evidence behind alert", "alert evidence", "view evidence", "evidence for alert")):
            intent = "show_evidence"
        elif any(k in q_lower for k in ("find related", "related events", "find related events", "correlated events", "related telemetry")):
            intent = "find_related"
        elif any(k in q_lower for k in ("explain attack", "attack sequence", "explain kill chain", "explain sequence", "attack chain")):
            intent = "explain_attack"
        elif any(k in q_lower for k in ("recommend next", "what should i do", "recommended action", "next step", "recommended next step")):
            intent = "recommend_next_step"
        elif any(k in q_lower for k in ("prepare containment", "containment plan", "contain incident", "propose containment", "isolate plan")):
            intent = "prepare_containment"
        elif any(k in q_lower for k in ("verify endpoint isolated", "verify isolation", "check endpoint status", "is endpoint isolated", "is host isolated")):
            intent = "verify_isolation"

        # Extract IDs from query if not provided
        if not incident_id:
            inc_match = re.search(r"\b(INC-[a-zA-Z0-9_-]+)\b", user_query, re.IGNORECASE)
            if inc_match:
                incident_id = inc_match.group(1).upper()
        if not alert_id:
            alt_match = re.search(r"\b(ALT-[a-zA-Z0-9_-]+)\b", user_query, re.IGNORECASE)
            if alt_match:
                alert_id = alt_match.group(1).upper()

        # Lazy load correlation engine
        try:
            from redloop.assessment.incident_correlation import IncidentCorrelator, RelationshipType
            correlator = IncidentCorrelator.get_correlator()
        except Exception:
            correlator = None

        # Process by intent
        if intent == "investigate_incident":
            return cls._op_investigate_incident(user_query, incident_id, correlator, ctx)
        elif intent == "show_evidence":
            return cls._op_show_evidence(user_query, alert_id, correlator, ctx)
        elif intent == "find_related":
            return cls._op_find_related(user_query, entity_id, incident_id, correlator, ctx)
        elif intent == "explain_attack":
            return cls._op_explain_attack(user_query, incident_id, correlator, ctx)
        elif intent == "recommend_next_step":
            return cls._op_recommend_next_step(user_query, incident_id, correlator, ctx)
        elif intent == "prepare_containment":
            return cls._op_prepare_containment(user_query, incident_id, entity_id, correlator, ctx)
        elif intent == "verify_isolation":
            return cls._op_verify_isolation(user_query, entity_id, ctx)
        else:
            # Fallback to standard start_investigation
            task = cls.start_investigation(user_query, explicit_target=entity_id)
            return {
                "intent": "general_investigation",
                "investigation_id": task.investigation_id,
                "target_entity": task.target_entity,
                "state": task.state.value if hasattr(task.state, "value") else str(task.state),
                "summary": task.findings_summary,
                "evidence_citations": [f"Indicator: {ind}" for ind in task.extracted_indicators],
                "recommended_action": f"Execute playbook {task.recommended_playbook_id}" if task.recommended_playbook_id else "Collect further host telemetry",
                "requires_approval": bool(task.recommended_playbook_id),
            }

    @classmethod
    def _op_investigate_incident(
        cls,
        user_query: str,
        incident_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        if not incident_id and correlator:
            incidents = correlator.list_incidents(limit=1)
            if incidents:
                incident_id = incidents[0].incident_id

        if not incident_id:
            return {
                "intent": "investigate_incident",
                "status": "NOT_FOUND",
                "message": "No incident ID specified and no active incidents found in correlation ledger.",
                "evidence_citations": [],
            }

        inc = correlator.get_incident(incident_id) if correlator else None
        if not inc:
            return {
                "intent": "investigate_incident",
                "status": "NOT_FOUND",
                "incident_id": incident_id,
                "message": f"Incident '{incident_id}' not found in active correlation engine.",
                "evidence_citations": [],
            }

        citations = [
            f"Event Link: {lnk.event_id} ({lnk.relationship_type.value}) - Shared: {', '.join(lnk.shared_entities)} | Evidence ID: {lnk.evidence_id}"
            for lnk in inc.linked_events
        ]
        text_lines = [
            f"### Incident Investigation: {inc.incident_id} — {inc.title}",
            f"**Severity:** {inc.severity.value} | **Confidence:** {inc.confidence_score:.0%} | **Status:** {inc.status}",
            f"**Summary:** {inc.summary}",
            f"**Affected Entities:** {', '.join(inc.affected_entities) or 'None'}",
            f"**Primary Host:** {inc.primary_host or 'N/A'} | **Primary User:** {inc.primary_user or 'N/A'}",
            f"**Linked Events Count:** {len(inc.linked_events)}",
        ]
        if inc.mitre_tactics:
            text_lines.append(f"**MITRE ATT&CK Tactics:** {', '.join(inc.mitre_tactics)}")
        if inc.mitre_techniques:
            text_lines.append(f"**MITRE ATT&CK Techniques:** {', '.join(inc.mitre_techniques)}")
        if inc.telemetry_gaps:
            text_lines.append("\n**Identified Telemetry Gaps:**")
            for gap in inc.telemetry_gaps:
                text_lines.append(f"- [GAP] {gap}")

        return {
            "intent": "investigate_incident",
            "status": "COMPLETED",
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity.value,
            "confidence_score": inc.confidence_score,
            "affected_entities": inc.affected_entities,
            "linked_events_count": len(inc.linked_events),
            "evidence_citations": citations,
            "telemetry_gaps": inc.telemetry_gaps,
            "response_text": "\n".join(text_lines),
        }

    @classmethod
    def _op_show_evidence(
        cls,
        user_query: str,
        alert_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        if not alert_id:
            # Check context or fallback
            alert_id = ctx.get("alert_id")

        if not alert_id:
            return {
                "intent": "show_evidence",
                "status": "NOT_FOUND",
                "message": "No alert ID or evidence identifier provided in query.",
                "evidence_citations": [],
            }

        # Search incident links for this alert/event
        found_link = None
        found_inc_id = None
        if correlator:
            for inc in correlator.list_incidents(limit=20):
                for lnk in inc.linked_events:
                    if lnk.event_id == alert_id or lnk.evidence_id == alert_id:
                        found_link = lnk
                        found_inc_id = inc.incident_id
                        break
                if found_link:
                    break

        if found_link:
            return {
                "intent": "show_evidence",
                "status": "VERIFIED",
                "alert_or_event_id": alert_id,
                "incident_id": found_inc_id,
                "provider_id": found_link.provider_id,
                "relationship_type": found_link.relationship_type.value,
                "shared_entities": found_link.shared_entities,
                "correlation_rationale": found_link.correlation_rationale,
                "confidence_score": found_link.confidence_score,
                "evidence_id": found_link.evidence_id,
                "timestamp": found_link.timestamp,
                "response_text": (
                    f"### Evidence Provenance for `{alert_id}`\n\n"
                    f"- **Evidence Ledger ID:** `{found_link.evidence_id}`\n"
                    f"- **Provider Source:** `{found_link.provider_id}`\n"
                    f"- **Relationship Class:** `{found_link.relationship_type.value}`\n"
                    f"- **Shared Entities:** {', '.join(found_link.shared_entities)}\n"
                    f"- **Timestamp:** `{found_link.timestamp}`\n"
                    f"- **Rationale:** {found_link.correlation_rationale}\n"
                    f"- **Confidence Score:** {found_link.confidence_score:.0%}"
                ),
            }

        return {
            "intent": "show_evidence",
            "status": "NO_EVIDENCE_RECORD",
            "alert_or_event_id": alert_id,
            "message": f"No raw evidence record or correlation link found for '{alert_id}'. RedLoop strictly refuses to fabricate evidence.",
            "evidence_citations": [],
        }

    @classmethod
    def _op_find_related(
        cls,
        user_query: str,
        entity_id: str | None,
        incident_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        if not entity_id:
            # extract entity from query
            words = user_query.split()
            for w in words:
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", w) or re.match(r"^[A-Za-z0-9_-]+-(?:PC|FIN|SRV|PROD|DEV)\b", w, re.IGNORECASE):
                    entity_id = w
                    break

        if not entity_id and incident_id and correlator:
            inc = correlator.get_incident(incident_id)
            if inc and inc.affected_entities:
                entity_id = inc.affected_entities[0]

        if not entity_id:
            return {
                "intent": "find_related",
                "status": "NOT_FOUND",
                "message": "Specify an entity (IP, hostname, user account) or incident to find related events.",
                "related_events": [],
            }

        related: list[dict[str, Any]] = []
        if correlator:
            for inc in correlator.list_incidents(limit=20):
                for lnk in inc.linked_events:
                    if any(entity_id.lower() in ent.lower() for ent in lnk.shared_entities):
                        related.append({
                            "event_id": lnk.event_id,
                            "incident_id": inc.incident_id,
                            "relationship_type": lnk.relationship_type.value,
                            "shared_entities": lnk.shared_entities,
                            "provider_id": lnk.provider_id,
                            "evidence_id": lnk.evidence_id,
                            "confidence": lnk.confidence_score,
                            "timestamp": lnk.timestamp,
                        })

        return {
            "intent": "find_related",
            "status": "COMPLETED",
            "entity": entity_id,
            "match_count": len(related),
            "related_events": related,
            "response_text": (
                f"### Correlated Events for Entity `{entity_id}`\n\n"
                f"Found {len(related)} events linked across telemetry feeds.\n"
                + "\n".join(
                    f"- **{r['event_id']}** ({r['relationship_type']}) via `{r['provider_id']}` [Confidence: {r['confidence']:.0%}] — Evidence: `{r['evidence_id']}`"
                    for r in related[:10]
                )
            ),
        }

    @classmethod
    def _op_explain_attack(
        cls,
        user_query: str,
        incident_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        if not incident_id and correlator:
            incidents = correlator.list_incidents(limit=1)
            if incidents:
                incident_id = incidents[0].incident_id

        if not incident_id or not correlator:
            return {
                "intent": "explain_attack",
                "status": "NOT_FOUND",
                "message": "No incident found to explain attack sequence.",
            }

        inc = correlator.get_incident(incident_id)
        if not inc:
            return {
                "intent": "explain_attack",
                "status": "NOT_FOUND",
                "message": f"Incident '{incident_id}' not found.",
            }

        # Chronological progression
        sorted_links = sorted(inc.linked_events, key=lambda l: l.timestamp)
        steps: list[str] = []
        for idx, lnk in enumerate(sorted_links, 1):
            steps.append(
                f"{idx}. **[{lnk.timestamp}]** `{lnk.event_id}` from provider `{lnk.provider_id}`: "
                f"{lnk.correlation_rationale} (Relationship: {lnk.relationship_type.value}, Evidence: `{lnk.evidence_id}`)"
            )

        tactics_str = ", ".join(inc.mitre_tactics) if inc.mitre_tactics else "Unclassified"
        techniques_str = ", ".join(inc.mitre_techniques) if inc.mitre_techniques else "None"

        narrative = (
            f"### Attack Sequence Reconstruction: `{inc.incident_id}`\n\n"
            f"**Attack Path Tactics:** {tactics_str}\n"
            f"**Identified Techniques:** {techniques_str}\n\n"
            f"**Progression Timeline ({len(sorted_links)} stages):**\n"
            + ("\n".join(steps) if steps else "No chronologically linked events recorded.")
            + "\n\n**Confidence & Gaps:** "
            + (f"Telemetry confidence is {inc.confidence_score:.0%}. " if inc.confidence_score else "")
            + (f"Evidence gaps noted: {'; '.join(inc.telemetry_gaps)}" if inc.telemetry_gaps else "Complete attack chain corroborated.")
        )

        return {
            "intent": "explain_attack",
            "status": "COMPLETED",
            "incident_id": inc.incident_id,
            "tactics": inc.mitre_tactics,
            "techniques": inc.mitre_techniques,
            "timeline_steps": steps,
            "response_text": narrative,
        }

    @classmethod
    def _op_recommend_next_step(
        cls,
        user_query: str,
        incident_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        recommendations: list[dict[str, Any]] = []

        inc = correlator.get_incident(incident_id) if (correlator and incident_id) else None

        if inc and inc.telemetry_gaps:
            recommendations.append({
                "priority": "HIGH",
                "category": "EVIDENCE_COLLECTION",
                "action": "Triage missing telemetry logs",
                "details": f"Ingest logs for gaps: {', '.join(inc.telemetry_gaps[:2])}",
                "requires_approval": False,
            })

        if inc and inc.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL):
            primary_h = inc.primary_host or (inc.affected_entities[0] if inc.affected_entities else "TARGET-HOST")
            recommendations.append({
                "priority": "CRITICAL",
                "category": "CONTAINMENT",
                "action": f"Request approval to isolate host '{primary_h}'",
                "details": "High/Critical severity incident with corroborated threat indicators requires network containment.",
                "requires_approval": True,
                "playbook_id": "PB-MALWARE",
            })

        if not recommendations:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "INVESTIGATION",
                "action": "Review IOC reputation and search cross-endpoint telemetry",
                "details": "Query local IOC repository and external threat intelligence for detected artifacts.",
                "requires_approval": False,
            })

        rec_text = "### Recommended Autonomous Next Steps\n\n" + "\n".join(
            f"- **[{r['priority']}]** {r['action']} — *{r['details']}* (Requires Authorization: `{r['requires_approval']}`)"
            for r in recommendations
        )

        return {
            "intent": "recommend_next_step",
            "incident_id": incident_id,
            "recommendations": recommendations,
            "response_text": rec_text,
        }

    @classmethod
    def _op_prepare_containment(
        cls,
        user_query: str,
        incident_id: str | None,
        entity_id: str | None,
        correlator: Any,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        inc = correlator.get_incident(incident_id) if (correlator and incident_id) else None
        target = entity_id or (inc.primary_host if inc else None) or (inc.affected_entities[0] if (inc and inc.affected_entities) else "192.168.1.100")

        containment_plan = {
            "plan_id": f"cont-plan-{uuid.uuid4().hex[:6]}",
            "incident_id": incident_id or "INC-UNASSIGNED",
            "target_resource": target,
            "proposed_actions": [
                {
                    "action_name": "isolate_endpoint",
                    "provider": "edr_defender",
                    "resource_id": target,
                    "destructive": False,
                    "reversible": True,
                },
                {
                    "action_name": "block_network_egress",
                    "provider": "perimeter_firewall",
                    "resource_id": target,
                    "destructive": False,
                    "reversible": True,
                },
            ],
            "approval_required": True,
            "governance_rule": "Cryptographic multi-attribute approval token required before external dispatch.",
            "rollback_strategy": "Invoke unisolate_endpoint / remove_firewall_rule upon incident triage resolution.",
        }

        resp_text = (
            f"### Containment Plan: `{containment_plan['plan_id']}`\n\n"
            f"- **Target Resource:** `{target}`\n"
            f"- **Associated Incident:** `{containment_plan['incident_id']}`\n"
            f"- **Proposed Action 1:** `isolate_endpoint` on provider `edr_defender` (Reversible)\n"
            f"- **Proposed Action 2:** `block_network_egress` (Reversible)\n\n"
            f"> [!IMPORTANT]\n"
            f"> Execution-time authorization is ENFORCED. No containment action will be dispatched without an authorized approval capability token."
        )

        return {
            "intent": "prepare_containment",
            "status": "PLAN_PREPARED",
            "containment_plan": containment_plan,
            "response_text": resp_text,
        }

    @classmethod
    def _op_verify_isolation(
        cls,
        user_query: str,
        entity_id: str | None,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        target = entity_id or ctx.get("endpoint") or ctx.get("host")
        if not target:
            match = re.search(r"\b(?:host|endpoint|machine|device)\s+([A-Za-z0-9_.-]+)\b", user_query, re.IGNORECASE)
            if match:
                target = match.group(1)

        if not target:
            return {
                "intent": "verify_isolation",
                "status": "TARGET_REQUIRED",
                "message": "Specify the host or endpoint to verify isolation status.",
            }

        # Check real provider connectivity / registry
        try:
            from redloop.integrations.registry import IntegrationRegistry
            from redloop.integrations.base import ProviderStatus
            reg = IntegrationRegistry.get_registry()
            defender = reg.get("edr_defender")
            cs = reg.get("edr_crowdstrike")

            provider_statuses = []
            if defender:
                provider_statuses.append(f"Defender: {defender.status.value}")
            if cs:
                provider_statuses.append(f"CrowdStrike: {cs.status.value}")
            prov_str = ", ".join(provider_statuses) if provider_statuses else "No EDR providers configured"
        except Exception:
            prov_str = "Integration registry offline"

        return {
            "intent": "verify_isolation",
            "target": target,
            "isolation_status": "NOT_ISOLATED_OR_UNVERIFIED",
            "provider_status": prov_str,
            "verified_with_live_edr": False,
            "response_text": (
                f"### Endpoint Isolation Verification: `{target}`\n\n"
                f"- **Current State:** `NOT_ISOLATED_OR_UNVERIFIED`\n"
                f"- **Provider Status:** {prov_str}\n"
                f"- **Evidence:** No confirmed host isolation telemetry received from active EDR providers.\n\n"
                f"> [!NOTE]\n"
                f"> RedLoop never fabricates isolation status when providers are unconfigured or offline."
            ),
        }

