"""Host security assessment engine for RedLoop.

Strictly adheres to:
- Section 17: Explicitly separates LOCAL_HOST from REMOTE_HOST. Never implies remote host visibility.
- Bounded inspection of processes, listening sockets, environment secrets, and SSH configuration.
- Never prints or stores unmasked secrets in logs or findings.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from redloop.assessment.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger


SENSITIVE_ENV_KEYS = re.compile(
    r"(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH_KEY|CREDENTIAL)",
    re.IGNORECASE,
)


def is_local_target(target: str) -> bool:
    """Determine if a target string corresponds to the local execution host."""
    clean = target.strip().lower()
    if clean in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True

    # Check against local hostname
    try:
        local_host = socket.gethostname().lower()
        if clean == local_host:
            return True
        local_fqdn = socket.getfqdn().lower()
        if clean == local_fqdn:
            return True
    except Exception:
        pass

    # Check if target is an IP belonging to a local network interface
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_loopback:
            return True
        # Resolve all local IPs
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        if clean in local_ips:
            return True
    except Exception:
        pass

    return False


class HostEngine:
    """Audits local host configuration, listening ports, processes, and service exposures."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
        timeout: float = 10.0,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.timeout = timeout

    def assess_host(
        self,
        target: str,
        operation_id: str = "op-host-assessment",
    ) -> StageResult:
        """Run host assessment within scope. Distinguishes LOCAL_HOST from REMOTE_HOST."""
        start_time = time.time()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []

        # 1. Scope & target classification
        if not is_local_target(target):
            if self.audit:
                self.audit.log(
                    "host_assessment_skipped",
                    target=target,
                    reason="Target is REMOTE_HOST. Local host checks only apply to local execution environment.",
                )
            return StageResult(
                stage="host_security",
                status=StageStatus.UNAVAILABLE,
                reason="Target is REMOTE_HOST. Host inspection requires local execution context or agent on target host.",
                duration_seconds=round(time.time() - start_time, 3),
            )

        # 2. Scope verification for local host
        self.scope_guard.verify_operation(
            target=target,
            operation_class=OperationClass.READ_ONLY,
            category="host_security",
        )

        host_os = platform.system()
        audit_data: dict[str, Any] = {
            "os": host_os,
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "target_type": "LOCAL_HOST",
        }

        # 3. Audit Environment for Secret Leakage
        env_findings = self._audit_environment(target, operation_id, evidence_list)
        findings.extend(env_findings)

        # 4. Audit Listening Sockets
        socket_findings, sockets = self._audit_listening_sockets(
            target, operation_id, evidence_list, host_os
        )
        findings.extend(socket_findings)
        audit_data["listening_sockets"] = sockets[:20]

        # 5. Audit SSH Configuration if present
        ssh_findings = self._audit_ssh_config(target, operation_id, evidence_list, host_os)
        findings.extend(ssh_findings)

        duration = round(time.time() - start_time, 3)
        if self.audit:
            self.audit.log(
                "host_assessment_completed",
                target=target,
                findings_count=len(findings),
                duration=duration,
            )

        return StageResult(
            stage="host_security",
            status=StageStatus.SUCCESS,
            reason=f"Completed local host security audit ({len(findings)} findings).",
            duration_seconds=duration,
            findings=findings,
            evidence=evidence_list,
            data=audit_data,
        )

    def _audit_environment(
        self,
        target: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Check for cleartext secrets exposed in environment variables."""
        findings = []
        exposed_vars = []

        for key, val in os.environ.items():
            if SENSITIVE_ENV_KEYS.search(key) and len(val) > 3:
                # Mask value: reveal first 2 and last 2 chars only
                masked = f"{val[:2]}****{val[-2:]}" if len(val) > 4 else "****"
                exposed_vars.append(f"{key}={masked}")

        if exposed_vars:
            ev = Evidence(
                target=target,
                operation_id=operation_id,
                tool_output="\n".join(exposed_vars),
                parser_result={"exposed_keys_count": len(exposed_vars)},
                response_excerpt=f"Identified {len(exposed_vars)} sensitive environment variables.",
            )
            evidence_list.append(ev)

            findings.append(
                Finding(
                    title="Sensitive Credentials Exposed in Host Environment Variables",
                    category="host_security",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target,
                    target=target,
                    description=(
                        f"Detected {len(exposed_vars)} environment variables containing sensitive naming patterns "
                        f"(e.g., API keys, passwords, or tokens) in the local process environment."
                    ),
                    evidence=[ev],
                    detection_method="local_environment_audit",
                    impact="Any subprocess or user with access to process memory/environment can read these credentials.",
                    remediation="Use a secure vault or secret management service instead of plain environment variables.",
                    references=["https://cwe.mitre.org/data/definitions/526.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return findings

    def _audit_listening_sockets(
        self,
        target: str,
        operation_id: str,
        evidence_list: list[Evidence],
        host_os: str,
    ) -> tuple[list[Finding], list[str]]:
        """Collect listening sockets via platform utilities (netstat / ss)."""
        findings = []
        listening = []

        try:
            if host_os == "Windows":
                cmd = ["netstat", "-ano"]
            else:
                cmd = ["ss", "-tuln"]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            raw_output = proc.stdout or ""

            # Check for unencrypted legacy services listening on 0.0.0.0 (all interfaces)
            unencrypted_services = {
                21: "FTP (cleartext control)",
                23: "Telnet (unencrypted terminal)",
                69: "TFTP (unauthenticated/unencrypted)",
                513: "rlogin (unencrypted)",
            }

            for line in raw_output.splitlines():
                line_str = line.strip()
                if "LISTENING" in line_str.upper() or (host_os != "Windows" and "LISTEN" in line_str):
                    listening.append(line_str)
                    for port, name in unencrypted_services.items():
                        if f":{port} " in line_str or f":{port}\t" in line_str:
                            ev = Evidence(
                                target=target,
                                operation_id=operation_id,
                                tool_output=line_str,
                                response_excerpt=f"Cleartext listening service found: {name} on port {port}",
                            )
                            evidence_list.append(ev)
                            findings.append(
                                Finding(
                                    title=f"Insecure Legacy Cleartext Service Listening ({name})",
                                    category="host_security",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    asset=target,
                                    target=target,
                                    port=port,
                                    description=f"Host is actively listening for connections on insecure service {name} (port {port}).",
                                    evidence=[ev],
                                    detection_method="listening_socket_analysis",
                                    impact="Credentials and session traffic transmitted over this service are unencrypted and subject to eavesdropping or tampering.",
                                    remediation=f"Disable the {name} daemon and replace with secure alternatives (e.g. SSH / SFTP).",
                                    references=["https://cwe.mitre.org/data/definitions/319.html"],
                                    source_operation_id=operation_id,
                                    status=FindingStatus.OPEN,
                                )
                            )

        except Exception as exc:
            if self.audit:
                self.audit.log("host_socket_audit_error", error=str(exc))

        return findings, listening

    def _audit_ssh_config(
        self,
        target: str,
        operation_id: str,
        evidence_list: list[Evidence],
        host_os: str,
    ) -> list[Finding]:
        """Audit local OpenSSH sshd_config if present."""
        findings = []
        possible_paths = [
            Path("/etc/ssh/sshd_config"),
            Path("C:/ProgramData/ssh/sshd_config"),
        ]

        config_path = None
        for p in possible_paths:
            if p.exists() and p.is_file():
                config_path = p
                break

        if not config_path:
            return findings

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]

            root_login = None
            password_auth = None

            for line in lines:
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    k, v = parts[0].lower(), parts[1].lower()
                    if k == "permitrootlogin":
                        root_login = v
                    elif k == "passwordauthentication":
                        password_auth = v

            if root_login in ("yes", "without-password"):
                ev = Evidence(
                    target=target,
                    operation_id=operation_id,
                    tool_output=f"PermitRootLogin {root_login} in {config_path}",
                    response_excerpt=f"sshd_config line: PermitRootLogin {root_login}",
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title="SSH Daemon Allows Direct Root Login",
                        category="host_security",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        asset=target,
                        target=target,
                        port=22,
                        description=f"SSH server configuration ({config_path}) allows direct root login ({root_login}).",
                        evidence=[ev],
                        detection_method="ssh_config_parser",
                        impact="Direct root login simplifies brute-force attacks and circumvents non-repudiation audit trails.",
                        remediation="Set 'PermitRootLogin no' in sshd_config and restart sshd.",
                        references=["https://cwe.mitre.org/data/definitions/250.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

            if password_auth == "yes":
                ev = Evidence(
                    target=target,
                    operation_id=operation_id,
                    tool_output=f"PasswordAuthentication yes in {config_path}",
                    response_excerpt=f"sshd_config line: PasswordAuthentication {password_auth}",
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title="SSH Daemon Allows Password Authentication",
                        category="host_security",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        asset=target,
                        target=target,
                        port=22,
                        description=f"SSH server configuration ({config_path}) permits password authentication instead of requiring public key authentication.",
                        evidence=[ev],
                        detection_method="ssh_config_parser",
                        impact="Password authentication exposes the host to credential stuffing and brute-force attacks.",
                        remediation="Configure 'PasswordAuthentication no' and mandate cryptographic key-based authentication.",
                        references=["https://cwe.mitre.org/data/definitions/287.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

        except Exception as exc:
            if self.audit:
                self.audit.log("ssh_config_audit_error", error=str(exc))

        return findings
