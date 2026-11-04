"""SOC Incident Response Playbooks Engine (Phase 5).

Provides 8 structured, actionable response playbooks:
1. PB-PHISH: Phishing Investigation & Triage
2. PB-CRED: Suspected Credential Compromise & Session Revocation
3. PB-BRUTE: Brute-Force Activity & Perimeter Containment
4. PB-PSHELL: Suspicious Obfuscated PowerShell Execution
5. PB-MALWARE: Malware Indicator Triage & Host Quarantine
6. PB-WEB: Web Attack (SQLi / Traversal / Web Shell) Remediation
7. PB-EXFIL: Potential Data Exfiltration & Channel Blocking
8. PB-OUTBOUND: Suspicious Outbound C2 Connection Disruption

Security Policy:
All containment and state-changing actions are recommendation-only or require
explicit per-action human approval (requires_approval=True). Never executes
destructive changes automatically without authorized approval audit.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PlaybookStepStatus(str, Enum):
    PENDING = "PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"


@dataclass
class PlaybookStep:
    step_id: str
    stage: int
    name: str
    description: str
    decision_point: str
    recommended_action: str
    action_command: str | None = None
    requires_approval: bool = True
    approval_status: PlaybookStepStatus = PlaybookStepStatus.PENDING
    approver: str | None = None
    approval_timestamp: str | None = None
    execution_result: str | None = None
    containment_flag: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["approval_status"] = self.approval_status.value if hasattr(self.approval_status, "value") else str(self.approval_status)
        return d


@dataclass
class ResponsePlaybook:
    playbook_id: str
    title: str
    category: str
    trigger_conditions: list[str]
    required_evidence: list[str]
    steps: list[PlaybookStep]
    containment_guidance: list[str]
    recovery_steps: list[str]
    verification_steps: list[str]
    rollback_plan: str
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "title": self.title,
            "category": self.category,
            "trigger_conditions": self.trigger_conditions,
            "required_evidence": self.required_evidence,
            "steps": [s.to_dict() for s in self.steps],
            "containment_guidance": self.containment_guidance,
            "recovery_steps": self.recovery_steps,
            "verification_steps": self.verification_steps,
            "rollback_plan": self.rollback_plan,
            "audit_events": self.audit_events,
        }


class SOCPlaybookEngine:
    """Manages and executes SOC incident response playbooks with explicit human approval enforcement."""

    _PLAYBOOKS: dict[str, ResponsePlaybook] = {}

    @classmethod
    def _initialize_catalog(cls) -> None:
        if cls._PLAYBOOKS:
            return

        # 1. PB-CRED: Suspected Credential Compromise
        cls._PLAYBOOKS["PB-CRED"] = ResponsePlaybook(
            playbook_id="PB-CRED",
            title="Suspected Credential Compromise & Session Revocation",
            category="Identity & Access",
            trigger_conditions=[
                "Successful authentication following 3+ failed logins",
                "Logon from anomalous geographical location or Tor exit node",
                "Credential exposure detected in breach repository",
            ],
            required_evidence=[
                "Authentication logs (/var/log/auth.log or Event ID 4624/4625)",
                "Source IP address and User-Agent telemetry",
                "Account username and role privileges",
            ],
            steps=[
                PlaybookStep(
                    step_id="step-cred-1",
                    stage=1,
                    name="Triage & Session Verification",
                    description="Inspect authentication logs to confirm whether logon source IP is foreign or unauthorized.",
                    decision_point="Is the logon origin an authorized corporate subnet/VPN?",
                    recommended_action="If IP is anomalous, flag account for immediate containment.",
                    requires_approval=False,
                    approval_status=PlaybookStepStatus.EXECUTED,
                ),
                PlaybookStep(
                    step_id="step-cred-2",
                    stage=2,
                    name="Account Session Invalidation & Temporary Lockout",
                    description="Revoke active OAuth/Kerberos refresh tokens and temporarily disable account password.",
                    decision_point="Confirm account containment to prevent unauthorized lateral movement.",
                    recommended_action="Execute directory lockout command via administrative CLI.",
                    action_command="sudo passwd -l <username> && sudo pkill -u <username>",
                    requires_approval=True,
                    containment_flag=True,
                ),
                PlaybookStep(
                    step_id="step-cred-3",
                    stage=3,
                    name="Forced Password Reset & MFA Enrollment",
                    description="Trigger mandatory password rotation and re-verify MFA authenticator binding.",
                    decision_point="Has the user confirmed identity out-of-band?",
                    recommended_action="Issue single-use temporary password and force rotation on next logon.",
                    requires_approval=True,
                ),
            ],
            containment_guidance=[
                "Disable active user sessions across all SaaS and internal bastions.",
                "Block malicious source IP address on perimeter edge firewall.",
            ],
            recovery_steps=[
                "Verify no persistence mechanisms (SSH authorized_keys, scheduled tasks) were added during compromised session.",
                "Re-enable account upon verified user password rotation.",
            ],
            verification_steps=[
                "Confirm previous session tokens return 401 Unauthorized.",
                "Verify subsequent logon attempts from malicious IP fail.",
            ],
            rollback_plan="sudo passwd -u <username> (Unlocks account if confirmed false alarm)",
        )

        # 2. PB-BRUTE: Authentication Brute-Force Containment
        cls._PLAYBOOKS["PB-BRUTE"] = ResponsePlaybook(
            playbook_id="PB-BRUTE",
            title="Authentication Brute-Force Perimeter Containment",
            category="Network & Authentication",
            trigger_conditions=["5+ failed logins from single IP within 5 minutes"],
            required_evidence=["Firewall or SSH authentication logs", "Attacker source IP"],
            steps=[
                PlaybookStep(
                    step_id="step-brute-1",
                    stage=1,
                    name="Source Reputation & Scope Check",
                    description="Check source IP against internal subnets and WHOIS reputation.",
                    decision_point="Is the source IP an internal scanner or external attacker?",
                    recommended_action="If external and malicious, generate perimeter drop rule.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-brute-2",
                    stage=2,
                    name="Perimeter IP Firewall Blacklist",
                    description="Deploy temporary firewall drop rule restricting attacker source IP.",
                    decision_point="Approve perimeter drop rule for attacker source IP.",
                    recommended_action="Execute iptables or host firewall block.",
                    action_command="sudo iptables -I INPUT -s <source_ip> -j DROP",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Add attacker IP to Fail2ban or edge firewall blocklist for 24 hours."],
            recovery_steps=["Review SSH configuration to enforce publickey-only auth."],
            verification_steps=["Verify packets from source IP are dropped at ingress."],
            rollback_plan="sudo iptables -D INPUT -s <source_ip> -j DROP",
        )

        # 3. PB-PSHELL: Suspicious Obfuscated PowerShell Execution
        cls._PLAYBOOKS["PB-PSHELL"] = ResponsePlaybook(
            playbook_id="PB-PSHELL",
            title="Suspicious Obfuscated PowerShell & Script Containment",
            category="Endpoint & Process",
            trigger_conditions=["PowerShell launched with -enc or hidden window parameters"],
            required_evidence=["Sysmon Event ID 1", "Full CommandLine string", "Process GUID"],
            steps=[
                PlaybookStep(
                    step_id="step-ps-1",
                    stage=1,
                    name="Payload Decoding & Deobfuscation",
                    description="Decode Base64 Unicode string to reveal actual script operations.",
                    decision_point="Does decoded payload invoke network downloads (DownloadString, IEX)?",
                    recommended_action="Identify dropped files and target C2 IP addresses.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-ps-2",
                    stage=2,
                    name="Host Process Tree Termination",
                    description="Kill active malicious PowerShell process and child processes.",
                    decision_point="Approve termination of PID <process_id>.",
                    recommended_action="Execute process tree termination.",
                    action_command="Stop-Process -Id <process_id> -Force",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Isolate affected workstation from internal VLAN via switch ACL or EDR."],
            recovery_steps=["Scan host with offline AV/antimalware; inspect registry Run keys."],
            verification_steps=["Confirm process PID is no longer present in task list."],
            rollback_plan="Restart benign service if process was misidentified.",
        )

        # 4. PB-WEB: Web Application Attack (SQLi / Traversal / Web Shell)
        cls._PLAYBOOKS["PB-WEB"] = ResponsePlaybook(
            playbook_id="PB-WEB",
            title="Web Application Attack & Web Shell Neutralization",
            category="Web Application",
            trigger_conditions=["SQL injection or directory traversal attack detected in web logs"],
            required_evidence=["Nginx/Apache access log", "Request URI and POST body", "HTTP response status code"],
            steps=[
                PlaybookStep(
                    step_id="step-web-1",
                    stage=1,
                    name="HTTP Response Analysis",
                    description="Check whether target web server returned 200 OK or 403/404/500.",
                    decision_point="Did server execute payload successfully or return error?",
                    recommended_action="If 200 OK with anomalous response size, inspect web document root for created files.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-web-2",
                    stage=2,
                    name="WAF Rule Deployment or URL Path Blocking",
                    description="Inject modsecurity or Nginx location deny directive blocking malicious pattern.",
                    decision_point="Approve web server config snippet reload.",
                    recommended_action="Block URI path pattern at reverse proxy.",
                    action_command="echo 'deny <source_ip>;' >> /etc/nginx/conf.d/blocklist.conf && nginx -s reload",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Quarantine newly created files in document root created in the last 1 hour."],
            recovery_steps=["Apply software patch for vulnerable endpoint parameter."],
            verification_steps=["Re-test endpoint with harmless probe to verify 403 Forbidden."],
            rollback_plan="sed -i '/<source_ip>/d' /etc/nginx/conf.d/blocklist.conf && nginx -s reload",
        )

        # 5. PB-MALWARE: Malware Indicator Triage & Host Quarantine
        cls._PLAYBOOKS["PB-MALWARE"] = ResponsePlaybook(
            playbook_id="PB-MALWARE",
            title="Malware Indicator Triage & Endpoint Quarantine",
            category="Endpoint Threat",
            trigger_conditions=["Known malicious SHA-256 hash match"],
            required_evidence=["File path", "File hash", "Sysmon Event ID 11 or AV detection alert"],
            steps=[
                PlaybookStep(
                    step_id="step-mal-1",
                    stage=1,
                    name="Threat Intelligence Correlation",
                    description="Query VirusTotal/NVD for known malware family attribution.",
                    decision_point="Is the hash verified malicious across multiple vendors?",
                    recommended_action="If verified, immediately quarantine host and file.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-mal-2",
                    stage=2,
                    name="File Quarantine & Network Isolation",
                    description="Move file to quarantine directory and isolate host network interface.",
                    decision_point="Approve moving file to /var/quarantine and isolating network interface.",
                    recommended_action="Execute quarantine command.",
                    action_command="sudo mv <file_path> /var/quarantine/<file_hash>.bak",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Isolate endpoint to prevent worm lateral propagation."],
            recovery_steps=["Restore endpoint from clean golden image snapshot."],
            verification_steps=["Verify file is removed from original path and cannot execute."],
            rollback_plan="sudo mv /var/quarantine/<file_hash>.bak <file_path>",
        )

        # 6. PB-PHISH: Phishing Investigation
        cls._PLAYBOOKS["PB-PHISH"] = ResponsePlaybook(
            playbook_id="PB-PHISH",
            title="Phishing Investigation & Mailbox Remediation",
            category="Email Security",
            trigger_conditions=["Inbound email with failed SPF/DKIM and executable/ISO attachment"],
            required_evidence=["EML headers", "Authentication-Results", "Attachment hash", "Sender IP"],
            steps=[
                PlaybookStep(
                    step_id="step-phish-1",
                    stage=1,
                    name="Header & Attachment Analysis",
                    description="Inspect SPF/DKIM verification and scan attachment hashes.",
                    decision_point="Are sender authentication checks failed and attachments high-risk?",
                    recommended_action="Extract embedded URLs and query domain age and reputation.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-phish-2",
                    stage=2,
                    name="Mailbox Purge & Sender Domain Blacklist",
                    description="Purge phishing email from all recipient inboxes and block sender domain.",
                    decision_point="Approve enterprise-wide mailbox purge of Message-ID <msg_id>.",
                    recommended_action="Execute mailbox purge via mail gateway API.",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Block sender domain and IP at mail gateway."],
            recovery_steps=["Notify affected users who received message; check for credential submission."],
            verification_steps=["Confirm message is purged from Exchange/IMAP mailboxes."],
            rollback_plan="Restore message from mail quarantine archive.",
        )

        # 7. PB-OUTBOUND: Suspicious Outbound C2 Connection Disruption
        cls._PLAYBOOKS["PB-OUTBOUND"] = ResponsePlaybook(
            playbook_id="PB-OUTBOUND",
            title="Suspicious Outbound C2 Connection Disruption",
            category="Network Security",
            trigger_conditions=["Outbound connection to known C2 IP or DNS tunneling domain"],
            required_evidence=["Netflow or Sysmon Event ID 3", "Destination IP/Port", "Process ID"],
            steps=[
                PlaybookStep(
                    step_id="step-out-1",
                    stage=1,
                    name="Connection Triage & Socket Inspection",
                    description="Identify process ID maintaining active TCP socket to destination IP.",
                    decision_point="Is the connection benign software update or unauthorized C2?",
                    recommended_action="If unauthorized, terminate socket and block destination IP.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-out-2",
                    stage=2,
                    name="Outbound Firewall Null-Route",
                    description="Deploy null-route (blackhole) or firewall block for destination C2 IP.",
                    decision_point="Approve route nullification for <destination_ip>.",
                    recommended_action="Execute route blackhole command.",
                    action_command="sudo ip route add blackhole <destination_ip>",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Null-route C2 IP at router/firewall level."],
            recovery_steps=["Inspect internal host for installed rootkit or backdoor."],
            verification_steps=["Verify TCP SYN packets to destination IP are dropped immediately."],
            rollback_plan="sudo ip route del blackhole <destination_ip>",
        )

        # 8. PB-EXFIL: Potential Data Exfiltration Investigation
        cls._PLAYBOOKS["PB-EXFIL"] = ResponsePlaybook(
            playbook_id="PB-EXFIL",
            title="Potential Data Exfiltration & Channel Blocking",
            category="Data Protection",
            trigger_conditions=["Unusual outbound data transfer volume or cloud upload"],
            required_evidence=["Netflow byte counters", "Source host", "Destination cloud endpoint"],
            steps=[
                PlaybookStep(
                    step_id="step-ex-1",
                    stage=1,
                    name="Bandwidth & Data Volume Verification",
                    description="Verify byte count transmitted and identify local file handles.",
                    decision_point="Did data transfer exceed authorized threshold?",
                    recommended_action="Identify sensitive data accessed prior to transfer.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-ex-2",
                    stage=2,
                    name="Egress Port / Domain Firewall Block",
                    description="Enforce egress filtering blocking file sharing or storage endpoint.",
                    decision_point="Approve blocking egress traffic to destination endpoint.",
                    recommended_action="Deploy egress firewall block rule.",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Revoke user access to sensitive file shares pending forensic audit."],
            recovery_steps=["Assess regulatory disclosure requirements under GDPR/HIPAA if PII was accessed."],
            verification_steps=["Confirm transfer terminated and egress channel is inaccessible."],
            rollback_plan="Remove egress block rule once investigation completes.",
        )

    @classmethod
    def _reset_playbooks(cls) -> None:
        """Resets playbooks catalog to fresh unapproved state for testing."""
        cls._PLAYBOOKS.clear()
        cls._initialize_catalog()

    @classmethod
    def list_playbooks(cls) -> list[dict[str, Any]]:
        cls._initialize_catalog()
        return [p.to_dict() for p in cls._PLAYBOOKS.values()]

    @classmethod
    def get_playbook(cls, playbook_id: str) -> ResponsePlaybook | None:
        cls._initialize_catalog()
        return cls._PLAYBOOKS.get(playbook_id)

    @classmethod
    def approve_step(
        cls,
        playbook_id: str,
        step_id: str,
        approver: str = "security_lead",
        approved: bool = True,
    ) -> dict[str, Any]:
        """Applies explicit human approval/rejection to a containment response step."""
        pb = cls.get_playbook(playbook_id)
        if not pb:
            return {"success": False, "error": f"Playbook '{playbook_id}' not found."}

        target_step: PlaybookStep | None = None
        for s in pb.steps:
            if s.step_id == step_id:
                target_step = s
                break

        if not target_step:
            return {"success": False, "error": f"Step '{step_id}' not found in playbook '{playbook_id}'."}

        # Replay prevention: reject duplicate approval if already approved
        if target_step.approval_status == PlaybookStepStatus.APPROVED and approved is True:
            return {
                "success": False,
                "error": f"Step '{step_id}' has already been resolved with status '{target_step.approval_status.value}'. Replay attempt rejected.",
            }
        if target_step.approval_status == PlaybookStepStatus.EXECUTED:
            return {
                "success": False,
                "error": f"Step '{step_id}' has already been executed. Cannot modify approval.",
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        target_step.approver = approver
        target_step.approval_timestamp = now_iso

        if approved:
            target_step.approval_status = PlaybookStepStatus.APPROVED
            target_step.execution_result = (
                f"Action approved by {approver} at {now_iso}. "
                f"Ready for authorized execution: '{target_step.action_command or target_step.recommended_action}'"
            )
        else:
            target_step.approval_status = PlaybookStepStatus.REJECTED
            target_step.execution_result = f"Action explicitly rejected by {approver} at {now_iso}."

        audit_entry = {
            "timestamp": now_iso,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "approver": approver,
            "approved": approved,
            "action_command": target_step.action_command,
        }
        pb.audit_events.append(audit_entry)

        return {
            "success": True,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "status": target_step.approval_status.value,
            "audit_entry": audit_entry,
        }

    @classmethod
    def execute_step(
        cls,
        playbook_id: str,
        step_id: str,
        auth_token: str | None = None,
    ) -> dict[str, Any]:
        """Executes an approved containment step. Enforces human authorization and auth token."""
        pb = cls.get_playbook(playbook_id)
        if not pb:
            return {"success": False, "error": f"Playbook '{playbook_id}' not found."}

        target_step: PlaybookStep | None = None
        for s in pb.steps:
            if s.step_id == step_id:
                target_step = s
                break

        if not target_step:
            return {"success": False, "error": f"Step '{step_id}' not found in playbook '{playbook_id}'."}

        # Check authorization token
        if not auth_token or not auth_token.startswith("rl-auth-"):
            return {
                "success": False,
                "error": "Execution rejected: Missing or invalid authorization token.",
            }

        # Enforce prerequisite approval
        if target_step.requires_approval and target_step.approval_status != PlaybookStepStatus.APPROVED:
            return {
                "success": False,
                "error": (
                    f"Execution rejected: Step '{step_id}' requires explicit human approval before execution. "
                    f"Current status: {target_step.approval_status.value}"
                ),
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        target_step.approval_status = PlaybookStepStatus.EXECUTED
        target_step.execution_result = f"Action successfully executed under token {auth_token[:12]}... at {now_iso}."

        return {
            "success": True,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "status": target_step.approval_status.value,
            "execution_result": target_step.execution_result,
        }
